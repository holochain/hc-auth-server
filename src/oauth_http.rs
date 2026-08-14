//! Bridges this server's `reqwest` client to the `oauth2` crate's transport
//! trait.
//!
//! `oauth2` ships an [`AsyncHttpClient`] implementation, but only for the
//! `reqwest` version it depends on, which trails the one used here.
//! Implementing the trait ourselves keeps the whole server on a single
//! `reqwest`.

use oauth2::http;
use oauth2::{AsyncHttpClient, HttpClientError, HttpRequest, HttpResponse};
use std::future::Future;
use std::pin::Pin;

/// Error returned when an OAuth HTTP request fails.
pub type OAuthHttpError = HttpClientError<reqwest::Error>;

/// Result alias for [`OAuthHttpError`].
pub type OAuthHttpResult<T> = Result<T, OAuthHttpError>;

/// An HTTP client for OAuth requests, usable as an `oauth2` transport.
#[derive(Clone, Debug)]
pub struct OAuthHttpClient(reqwest::Client);

impl OAuthHttpClient {
    /// Builds a client for OAuth requests.
    ///
    /// Redirects are disabled, because following one on a token request would
    /// send the client credentials to whatever host the response points at.
    pub fn new() -> Result<Self, reqwest::Error> {
        reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map(Self)
    }
}

impl<'c> AsyncHttpClient<'c> for OAuthHttpClient {
    type Error = OAuthHttpError;

    type Future = Pin<
        Box<dyn Future<Output = OAuthHttpResult<HttpResponse>> + Send + 'c>,
    >;

    fn call(&'c self, request: HttpRequest) -> Self::Future {
        Box::pin(async move {
            let response = self
                .0
                .execute(request.try_into().map_err(Box::new)?)
                .await
                .map_err(Box::new)?;

            let mut builder = http::Response::builder()
                .status(response.status())
                .version(response.version());

            for (name, value) in response.headers() {
                builder = builder.header(name, value);
            }

            builder
                .body(response.bytes().await.map_err(Box::new)?.to_vec())
                .map_err(HttpClientError::Http)
        })
    }
}
