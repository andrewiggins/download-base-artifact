import github from "@actions/github";
import httpClient from "@actions/http-client";
import octokit from "@octokit/core";
import endpointPlugin from "@octokit/plugin-rest-endpoint-methods";
import paginatePlugin from "@octokit/plugin-paginate-rest";

// Mostly copied from: https://github.com/actions/toolkit/blob/cee7d92d1d02e3107c9b1387b9690b89096b67be/packages/github/src/utils.ts#L12
// Copied from there to allow for un-authed requests for local testing

const baseUrl = "https://api.github.com";
const hc = new httpClient.HttpClient();
const agent = hc.getAgent(baseUrl);

const defaults = {
	baseUrl,
	request: {
		agent,
	},
};

export function getTestClient() {
	if (process.env.GITHUB_TOKEN) {
		return github.getOctokit(process.env.GITHUB_TOKEN);
	} else {
		const GitHub = octokit.Octokit.plugin(
			endpointPlugin.restEndpointMethods,
			paginatePlugin.paginateRest
		).defaults(defaults);

		return new GitHub();
	}
}
