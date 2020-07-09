import github from "@actions/github";
import {
	OctokitResponse,
	ActionsGetWorkflowResponseData,
	ActionsGetWorkflowRunResponseData,
	ActionsGetArtifactResponseData,
} from "@octokit/types";

declare global {
	type GitHubClient = ReturnType<typeof github.getOctokit>;
	type GitHubContext = typeof github.context;
	type GitHubRepo = GitHubContext["repo"];

	type WorkflowData = ActionsGetWorkflowResponseData;
	type WorkflowRunData = ActionsGetWorkflowRunResponseData;
	type ArtifactData = ActionsGetArtifactResponseData;

	type WorkflowRunsAsyncIterator = AsyncIterableIterator<
		OctokitResponse<WorkflowRunData[]>
	>;

	type ArtifactsAsyncIterator = AsyncIterableIterator<
		OctokitResponse<ActionsGetArtifactResponseData[]>
	>;
}
