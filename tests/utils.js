const github = require("@actions/github");
const httpClient = require("@actions/http-client");
const octokit = require("@octokit/core");
const endpointPlugin = require("@octokit/plugin-rest-endpoint-methods");
const paginatePlugin = require("@octokit/plugin-paginate-rest");

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

function getTestClient() {
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

module.exports = {
	getTestClient,
};
