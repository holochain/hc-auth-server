use reqwest::header::{AUTHORIZATION, USER_AGENT};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct GitHubUser {
    pub login: String,
    //pub avatar_url: String,
}

#[derive(Debug, Deserialize)]
pub struct GitHubOrg {
    pub login: String,
}

#[derive(Debug, Deserialize)]
pub struct GitHubTeam {
    //pub slug: String,
    //pub name: String,
    pub organization: GitHubOrg,
}

pub struct GitHubClient {
    client: reqwest::Client,
    access_token: String,
}

impl GitHubClient {
    pub fn new(client: reqwest::Client, access_token: String) -> Self {
        Self {
            client,
            access_token,
        }
    }

    pub async fn get_user(&self) -> Result<GitHubUser, reqwest::Error> {
        self.client
            .get("https://api.github.com/user")
            .header(USER_AGENT, "rust-oauth-server")
            .header(AUTHORIZATION, format!("Bearer {}", self.access_token))
            .send()
            .await?
            .json::<GitHubUser>()
            .await
    }

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

    pub async fn list_user_teams(
        &self,
    ) -> Result<Vec<GitHubTeam>, reqwest::Error> {
        self.client
            .get("https://api.github.com/user/teams")
            .header(USER_AGENT, "rust-oauth-server")
            .header(AUTHORIZATION, format!("Bearer {}", self.access_token))
            .send()
            .await?
            .json::<Vec<GitHubTeam>>()
            .await
    }
}
