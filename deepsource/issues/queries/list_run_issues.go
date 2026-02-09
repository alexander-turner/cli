// Lists the issues reported for a specific commit (analysis run)
package issues

import (
	"context"
	"fmt"
	"regexp"

	"github.com/deepsourcelabs/cli/deepsource/issues"
	"github.com/deepsourcelabs/graphql"
	"github.com/pterm/pterm"
)

// commitSHAPattern validates that a commit OID looks like a hex SHA (6-40 chars).
var commitSHAPattern = regexp.MustCompile(`^[0-9a-fA-F]{6,40}$`)

const fetchRunIssuesQuery = `query GetRunIssues(
  $commitOid: String!
  $limit: Int!
) {
  run(commitOid: $commitOid) {
    status
    checks {
      edges {
        node {
          analyzer {
            name
            shortcode
          }
          status
          occurrences(first: $limit) {
            edges {
              node {
                path
                beginLine
                endLine
                issue {
                  title
                  shortcode
                  category
                  severity
                }
              }
            }
          }
        }
      }
    }
  }
}`

type RunIssuesListParams struct {
	CommitOID string
	Limit     int
}

type RunIssuesListRequest struct {
	Params RunIssuesListParams
}

type RunIssuesListResponse struct {
	Run struct {
		Status string `json:"status"`
		Checks struct {
			Edges []struct {
				Node struct {
					Analyzer struct {
						Name      string `json:"name"`
						Shortcode string `json:"shortcode"`
					} `json:"analyzer"`
					Status      string `json:"status"`
					Occurrences struct {
						Edges []struct {
							Node struct {
								Path      string `json:"path"`
								BeginLine int    `json:"beginLine"`
								EndLine   int    `json:"endLine"`
								Issue     struct {
									Title     string `json:"title"`
									Shortcode string `json:"shortcode"`
									Category  string `json:"category"`
									Severity  string `json:"severity"`
								} `json:"issue"`
							} `json:"node"`
						} `json:"edges"`
					} `json:"occurrences"`
				} `json:"node"`
			} `json:"edges"`
		} `json:"checks"`
	} `json:"run"`
}

// ValidateCommitOID checks that the provided string looks like a valid commit SHA.
func ValidateCommitOID(commitOID string) error {
	if !commitSHAPattern.MatchString(commitOID) {
		return fmt.Errorf("invalid commit SHA %q: must be a 6-40 character hex string", commitOID)
	}
	return nil
}

func (r RunIssuesListRequest) Do(ctx context.Context, client IGQLClient) ([]issues.Issue, error) {
	req := graphql.NewRequest(fetchRunIssuesQuery)
	req.Var("commitOid", r.Params.CommitOID)
	req.Var("limit", r.Params.Limit)

	// set header fields
	req.Header.Set("Cache-Control", "no-cache")
	tokenHeader := fmt.Sprintf("Bearer %s", client.GetToken())
	req.Header.Add("Authorization", tokenHeader)

	// run it and capture the response
	var respData RunIssuesListResponse
	if err := client.GQL().Run(ctx, req, &respData); err != nil {
		return nil, err
	}

	// Check if a run was found. A null/missing run object results in
	// zero-value fields. We check both Status and the presence of checks
	// to be resilient against future API changes where an empty status
	// might be valid.
	if respData.Run.Status == "" && len(respData.Run.Checks.Edges) == 0 {
		return nil, fmt.Errorf("no analysis run found for commit %s", r.Params.CommitOID)
	}

	var issuesData []issues.Issue
	for _, checkEdge := range respData.Run.Checks.Edges {
		check := checkEdge.Node

		// Warn when a check has a non-success status so the user knows
		// results may be incomplete.
		if check.Status != "" && check.Status != "SUCCESS" {
			pterm.Warning.Printf("Analyzer %q has status %s — results may be incomplete\n",
				check.Analyzer.Shortcode, check.Status)
		}

		for _, occEdge := range check.Occurrences.Edges {
			issueData := issues.Issue{
				IssueText:     occEdge.Node.Issue.Title,
				IssueCode:     occEdge.Node.Issue.Shortcode,
				IssueCategory: occEdge.Node.Issue.Category,
				IssueSeverity: occEdge.Node.Issue.Severity,
				Location: issues.Location{
					Path: occEdge.Node.Path,
					Position: issues.Position{
						BeginLine: occEdge.Node.BeginLine,
						EndLine:   occEdge.Node.EndLine,
					},
				},
				Analyzer: issues.AnalyzerMeta{
					Shortcode: check.Analyzer.Shortcode,
				},
			}
			issuesData = append(issuesData, issueData)
		}
	}

	// The GraphQL query applies $limit per-analyzer check, not globally.
	// Truncate to the requested limit so the user gets at most what they asked for.
	if r.Params.Limit > 0 && len(issuesData) > r.Params.Limit {
		issuesData = issuesData[:r.Params.Limit]
	}

	return issuesData, nil
}
