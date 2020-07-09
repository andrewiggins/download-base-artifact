import {
	OctokitResponse,
	ActionsGetWorkflowResponseData,
	ActionsGetWorkflowRunResponseData,
	ActionsGetArtifactResponseData,
} from "@octokit/types";

export type WorkflowData = ActionsGetWorkflowResponseData;
export type WorkflowRunData = ActionsGetWorkflowRunResponseData;
export type ArtifactData = ActionsGetArtifactResponseData;

export type WorkflowRunsAsyncIterator = AsyncIterableIterator<
	OctokitResponse<WorkflowRunData[]>
>;

export type ArtifactsAsyncIterator = AsyncIterableIterator<
	OctokitResponse<ActionsGetArtifactResponseData[]>
>;
