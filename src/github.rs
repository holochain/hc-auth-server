use reqwest::header::{AUTHORIZATION, USER_AGENT};
use serde::Deserialize;

/// Detailed information about a GitHub user.
#[derive(Debug, Deserialize)]
pub struct GitHubUser {
    /// The user's GitHub username.
    pub login: String,
    //pub avatar_url: String,
}

/// Detailed information about a GitHub organization.
#[derive(Debug, Deserialize)]
pub struct GitHubOrg {
    /// The organization's GitHub name/slug.
    pub login: String,
}

/// Detailed information about a GitHub team.
#[derive(Debug, Deserialize)]
pub struct GitHubTeam {
    //pub slug: String,
    //pub name: String,
    /// The organization the team belongs to.
    pub organization: GitHubOrg,
}

/// A client for interacting with the GitHub API.
pub struct GitHubClient {
    client: reqwest::Client,
    access_token: String,
}

impl GitHubClient {
    /// Creates a new GitHubClient with the provided HTTP client and access token.
    pub fn new(client: reqwest::Client, access_token: String) -> Self {
        Self {
            client,
            access_token,
        }
    }

    /// Fetches the authenticated user's profile information.
    pub async fn get_user(&self) -> Result<GitHubUser, reqwest::Error> {
        self.client
            .get("https://api.github.com/user")
            .header(USER_AGENT, "rust-oauth-server")
            .header(AUTHORIZATION, format!("Bearer {}", self.access_token))
            .send()
            .await?
            .error_for_status()?
            .json::<GitHubUser>()
            .await
    }

    /// Checks if the authenticated user is a member of a specific GitHub team.
    ///
    /// Returns true if the user is an active member, false otherwise.
    pub async fn is_team_member(
        &self,
        org: &str,
        team_slug: &str,
    ) -> Result<bool, reqwest::Error> {
        // According to GitHub API docs (Verify organization membership for a user)
        // GET /orgs/{org}/members/{username} is one way, but easier might be:
        // GET /user/memberships/orgs/{org} to see status usually?
        // Or for a specific team: GET /orgs/{org}/teams/{team_slug}/memberships/{username}

        let user = self.get_user().await?;
        let url = format!(
            "https://api.github.com/orgs/{}/teams/{}/memberships/{}",
            org, team_slug, user.login
        );

        let resp = self
            .client
            .get(&url)
            .header(USER_AGENT, "rust-oauth-server")
            .header(AUTHORIZATION, format!("Bearer {}", self.access_token))
            .send()
            .await?;

        // 200 OK means they are a member (active).
        // 404 means they are not a member (or team doesn't exist, or no permission).
        Ok(resp.status().is_success())
    }

    /// Lists the teams the authenticated user belongs to.
    pub async fn list_user_teams(
        &self,
    ) -> Result<Vec<GitHubTeam>, reqwest::Error> {
        self.client
            .get("https://api.github.com/user/teams")
            .header(USER_AGENT, "rust-oauth-server")
            .header(AUTHORIZATION, format!("Bearer {}", self.access_token))
            .send()
            .await?
            .error_for_status()?
            .json::<Vec<GitHubTeam>>()
            .await
    }
}
