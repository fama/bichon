//
// Copyright (c) 2025-2026 rustmailer.com (https://rustmailer.com)
//
// This file is part of the Bichon Email Archiving Project
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

use bichon_core::{
    common::auth::ClientContext,
    database::{find_impl, manager::DB_MANAGER},
    error::code::ErrorCode,
    settings::cli::SETTINGS,
    token::AccessTokenModel,
    users::{UserModel, DEFAULT_ADMIN_USER_ID},
    utils::rate_limit::RATE_LIMITER_MANAGER,
};
use governor::clock::{Clock, QuantaClock};
use poem::{
    web::{
        headers::{authorization::Bearer, Authorization, HeaderMapExt},
        RealIp,
    },
    Endpoint, FromRequest, Middleware, Request, RequestBody, Result,
};
use serde::Deserialize;
use std::{net::IpAddr, ops::Deref, sync::Arc};

use super::create_api_error_response;

/// Path prefix for endpoints whose ROOT-only access can be granted via the
/// in-container loopback bypass (`bichon_local_admin_bypass`). Kept narrow
/// on purpose: extending the allowlist requires a deliberate code change.
const LOCAL_ADMIN_BYPASS_PATHS: &[&str] = &["/api/v1/repair-blobs/"];

pub struct ApiGuard;

pub struct ApiGuardEndpoint<E> {
    ep: E,
}

impl<E: Endpoint> Middleware<E> for ApiGuard {
    type Output = ApiGuardEndpoint<E>;

    fn transform(&self, ep: E) -> Self::Output {
        ApiGuardEndpoint { ep }
    }
}

#[derive(Deserialize)]
struct Param {
    access_token: String,
}

impl<E: Endpoint> Endpoint for ApiGuardEndpoint<E> {
    type Output = E::Output;

    async fn call(&self, mut req: Request) -> Result<Self::Output> {
        if let Some(ctx) = try_local_admin_bypass(&req) {
            req.set_data(Arc::new(ctx));
            return self.ep.call(req).await;
        }
        let context = authorize_access(&req).await?;
        req.set_data(Arc::new(context));
        self.ep.call(req).await
    }
}

/// Returns a synthetic admin `ClientContext` when the request is eligible for
/// the in-container loopback bypass, otherwise `None` (normal auth applies).
///
/// All conditions must hold:
///   - `bichon_local_admin_bypass = true` in settings
///   - The request path matches one of `LOCAL_ADMIN_BYPASS_PATHS`
///   - The raw TCP remote address is a loopback IP (no proxy hop)
///   - The request carries no proxy-forwarding headers (defense-in-depth: a
///     local-only proxy forwarding external traffic would otherwise become a
///     bypass vector)
///   - The default admin user exists in the DB (so the synthesized context has
///     real ROOT-tier permissions through the existing `is_admin()` path)
fn try_local_admin_bypass(req: &Request) -> Option<ClientContext> {
    if !SETTINGS.bichon_local_admin_bypass {
        return None;
    }
    let path = req.uri().path();
    if !LOCAL_ADMIN_BYPASS_PATHS.iter().any(|p| path.starts_with(p)) {
        return None;
    }
    if !is_request_loopback(req) {
        return None;
    }
    if has_proxy_forward_headers(req) {
        return None;
    }
    let admin = find_impl::<UserModel>(DB_MANAGER.db(), &DEFAULT_ADMIN_USER_ID.to_string())
        .ok()
        .flatten()?;
    Some(ClientContext {
        ip_addr: parse_remote_ip(req),
        user: admin,
    })
}

fn is_request_loopback(req: &Request) -> bool {
    parse_remote_ip(req).map(|ip| ip.is_loopback()).unwrap_or(false)
}

/// Parse the TCP-level remote IP from `req.remote_addr()`. This deliberately
/// ignores X-Forwarded-For / X-Real-IP: the loopback check is about the actual
/// connection, not what a proxy claims.
fn parse_remote_ip(req: &Request) -> Option<IpAddr> {
    let s = req.remote_addr().to_string();
    // SocketAddr Display form is "ip:port" (IPv4) or "[ip]:port" (IPv6).
    // Strip the port and any brackets, then parse.
    let host = match s.rsplit_once(':') {
        Some((host, _port)) => host,
        None => s.as_str(),
    };
    let host = host.trim_start_matches('[').trim_end_matches(']');
    host.parse::<IpAddr>().ok()
}

fn has_proxy_forward_headers(req: &Request) -> bool {
    let h = req.headers();
    h.contains_key("x-forwarded-for")
        || h.contains_key("x-real-ip")
        || h.contains_key("forwarded")
}

pub struct WrappedContext(pub ClientContext);

impl Deref for WrappedContext {
    type Target = ClientContext;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<'a> FromRequest<'a> for WrappedContext {
    async fn from_request(req: &'a Request, _body: &mut RequestBody) -> Result<Self> {
        // ApiGuard already authenticated (or bypassed) and stashed the context
        // in request data. Reuse it instead of re-extracting from the bearer
        // header — without this fallback, the loopback bypass would be
        // overridden by a "Valid access token not found" error here.
        if let Some(ctx) = req.data::<Arc<ClientContext>>() {
            return Ok(WrappedContext((**ctx).clone()));
        }
        let ctx = extract_client_context(req).await?;
        Ok(WrappedContext(ctx))
    }
}

pub async fn extract_client_context(req: &Request) -> Result<ClientContext> {
    let ip_addr = RealIp::from_request_without_body(req)
        .await
        .map_err(|_| {
            create_api_error_response(
                "Failed to parse client IP address",
                ErrorCode::InvalidParameter,
            )
        })?
        .0
        .ok_or_else(|| {
            create_api_error_response(
                "Failed to parse client IP address",
                ErrorCode::InvalidParameter,
            )
        })?;
    // Extract access token from Bearer header or query params
    let bearer = req
        .headers()
        .typed_get::<Authorization<Bearer>>()
        .map(|auth| auth.0.token().to_string())
        .or_else(|| req.params::<Param>().ok().map(|param| param.access_token));

    let token = bearer.ok_or_else(|| {
        create_api_error_response("Valid access token not found", ErrorCode::PermissionDenied)
    })?;

    // Validate and update access token
    let user = AccessTokenModel::resolve_user_from_token(&token).map_err(|e| {
        create_api_error_response(&format!("{:#?}", e), ErrorCode::PermissionDenied)
    })?;

    return Ok(ClientContext {
        ip_addr: Some(ip_addr),
        user,
    });
}

pub async fn authorize_access(req: &Request) -> Result<ClientContext, poem::Error> {
    let context = extract_client_context(&req).await?;
    if let Some(access_control) = &context.user.acl {
        if let Some(ip_addr) = context.ip_addr {
            if let Some(whitelist) = &access_control.ip_whitelist {
                if !whitelist.contains(&ip_addr.to_string()) {
                    return Err(create_api_error_response(
                        &format!("IP {} not in whitelist", ip_addr),
                        ErrorCode::Forbidden,
                    ));
                }
            }
        }

        if let Some(rate_limit) = &access_control.rate_limit {
            if let Err(not_until) = RATE_LIMITER_MANAGER
                .check(context.user.id, rate_limit.clone())
                .await
            {
                let wait_duration = not_until.wait_time_from(QuantaClock::default().now());
                return Err(create_api_error_response(
                    &format!(
                        "Rate limit: {}/{}s. Retry after {}s",
                        rate_limit.quota,
                        rate_limit.interval,
                        wait_duration.as_secs()
                    ),
                    ErrorCode::TooManyRequest,
                ));
            }
        }
    }

    Ok(context)
}
