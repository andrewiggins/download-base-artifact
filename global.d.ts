import github from "@actions/github";

declare global {
  type GitHubClient = ReturnType<typeof github.getOctokit>;
  type GitHubContext = typeof github.context;

  interface Inputs {
    workflow?: string;
    artifact: string;
    path?: string;
  }
}
