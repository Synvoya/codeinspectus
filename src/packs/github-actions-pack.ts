import {
  GITHUB_ACTIONS_RULE_IDS,
  runGithubActionsSecurity,
} from "./github-actions/workflow-security.js";
import type { NativeDetectorPack } from "./types.js";

export const GITHUB_ACTIONS_PACK_LIMITATIONS = [
  "Detects two exact GitHub Actions workflow risks: attacker-controlled GitHub context expressions embedded directly in run scripts, and pull_request_target workflows that check out and execute untrusted pull request code.",
  "Expression injection covers a documented static set of issue, pull request, comment, review, page, commit, email, name, and head-ref properties; bracket notation, aliases, custom actions, generated scripts, and inter-step dataflow are outside this pack.",
  "Pwn-request analysis requires pull_request_target, a recognized untrusted actions/checkout ref, checkout v1-v6 or explicit allow-unsafe-pr-checkout, the default workspace, and a subsequent recognized build/test/script command or local action.",
  "workflow_run, issue_comment code fetches, downloaded artifacts, non-checkout git/gh fetches, non-default checkout paths, self-hosted runner isolation, deployed repository settings, organization policy, and complete CI/CD security coverage are outside this pack.",
  "Only direct .github/workflows/*.yml and *.yaml files are parsed as strict YAML 1.2; malformed, unsupported, unreadable, symbolic-link, or oversized workflows fail closed and are reported in pack coverage.",
  "Workflow reads are bounded to 1 MiB per file, 512 files, and 16 MiB total; target actions, expressions, scripts, and repository code are never evaluated or executed.",
] as const;

/** First-party GitHub Actions checked-in workflow pack; no target code executes. */
export const githubActionsPack: NativeDetectorPack = {
  id: "github-actions",
  version: "1.0.0",
  scannerKind: "ai",
  languages: ["yaml"],
  frameworks: [],
  platforms: ["github-actions"],
  limitations: GITHUB_ACTIONS_PACK_LIMITATIONS,
  isApplicable: (detectedTechnologies) =>
    detectedTechnologies.some((technology) => technology.id === "github-actions"),
  createAnalyzers: (target) => [{
    id: "github-actions-workflow-security",
    components: [
      "pack:github-actions:dispatch",
      "github-actions:yaml-workflow-parser",
      "ai:github-actions-expression-injection",
      "ai:github-actions-pwn-request",
    ],
    ruleIds: GITHUB_ACTIONS_RULE_IDS,
    run: () => runGithubActionsSecurity(target),
  }],
};
