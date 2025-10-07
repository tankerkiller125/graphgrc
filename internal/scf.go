package internal

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strings"

	md "github.com/go-spectest/markdown"

	"github.com/xuri/excelize/v2"
)

type ControlHeader string
type ControlValue string
type Framework string
type FrameworkControlID string
type SCFControlID string

type Control map[ControlHeader]ControlValue
type SCFControls map[SCFControlID]Control

type ControlMapping map[Framework][]FrameworkControlID

func (c ControlMapping) MapsToControls() bool {
	for _, mappings := range c {
		if len(mappings) > 0 {
			return true
		}
	}
	return false
}

type SCFControlMappings map[SCFControlID]ControlMapping

const Description = "Description"
const ComplianceMethods = "Compliance Methods"
const ControlQuestions = "Control Questions"
const NotPerformed = "Not Performed"
const PerformedInternally = "Performed Informally"
const PlannedAndTracked = "Planned & Tracked"
const WellDefined = "Well Defined"
const QuantitativelyControlled = "Quantitatively Controlled"
const ContinuouslyImproving = "Continuously Improving"

var SCFColumnMapping = map[string]ControlHeader{
	Description:              "Secure Controls Framework (SCF) Control Description",
	ControlQuestions:         "SCF Control Question",
	NotPerformed:             "SP-CMM 0 Not Performed",
	PerformedInternally:      "SP-CMM 1 Performed Informally",
	PlannedAndTracked:        "SP-CMM 2 Planned & Tracked",
	WellDefined:              "SP-CMM 3 Well Defined",
	QuantitativelyControlled: "SP-CMM 4 Quantitatively Controlled",
	ContinuouslyImproving:    "SP-CMM 5 Continuously Improving",
}

var SupportedFrameworks = map[Framework]ControlHeader{
	"SOC 2":     "AICPA TSC 2017 (Controls)",
	"GDPR":      "EMEA EU GDPR",
	"ISO 27001": "ISO 27001 v2022",
	"ISO 27002": "ISO 27002 v2022",
}

var SCFControlFamilyMapping = map[string]string{
	"AAT": "Artificial and Autonomous Technology",
	"AST": "Asset Management",
	"BCD": "Business Continuity & Disaster Recovery",
	"CAP": "Capacity & Performance Planning",
	"CHG": "Change Management",
	"CLD": "Cloud Security",
	"CFG": "Configuration Management",
	"CPL": "Compliance",
	"CRY": "Cryptographic Protections",
	"DCH": "Data Classification & Handling",
	"EMB": "Embedded Technology",
	"END": "Endpoint Security",
	"GOV": "Cybersecurity & Data Privacy Governance",
	"HRS": "Human Resources Security",
	"IAO": "Information Assurance",
	"IAC": "Identification & Authentication",
	"IRO": "Incident Response",
	"MON": "Continuous Monitoring",
	"MNT": "Maintenance",
	"MDM": "Mobile Device Management",
	"NET": "Network Security",
	"OPS": "Security Operations",
	"PES": "Physical & Environmental Security",
	"PRI": "Data Privacy",
	"PRM": "Project & Resource Management",
	"RSK": "Risk Management",
	"SAT": "Security Awareness & Training",
	"SEA": "Secure Engineering & Architecture",
	"TDA": "Technology Development & Acquisition",
	"THR": "Threat Management",
	"TPM": "Third-Party Management",
	"VPM": "Vulnerability & Patch Management",
	"WEB": "Web Security",
}

func ReturnSCFControls(url string, getFile bool) (SCFControls, error) {
	controls := map[SCFControlID]Control{}
	if getFile {
		resp, err := http.Get(url)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		out, err := os.Create("scf.xlsx")
		if err != nil {
			return nil, err
		}
		defer out.Close()
		io.Copy(out, resp.Body)
	}

	f, err := excelize.OpenFile("scf.xlsx")
	if err != nil {
		return nil, err
	}
	defer func() {
		if err := f.Close(); err != nil {
			log.Println(err)
		}
	}()
	rows, err := f.GetRows("SCF 2023.4")
	if err != nil {
		return nil, err
	}
	headers := []ControlHeader{}
	for idx, row := range rows {
		if idx == 0 {
			for _, header := range row {
				headers = append(headers, ControlHeader(strings.ReplaceAll(header, "\n", " ")))
			}
		} else {
			scfControlID := fmt.Sprintf("%s - %s", row[2], strings.TrimSpace(strings.ReplaceAll(row[1], "\n", " ")))
			control := Control{}
			for idx, val := range row {
				control[headers[idx]] = ControlValue(strings.ReplaceAll(val, "▪", "-"))
			}
			controls[SCFControlID(scfControlID)] = control
		}
	}
	file, err := json.MarshalIndent(controls, "", " ")
	if err != nil {
		return controls, err
	}
	err = os.WriteFile("scf.json", file, 0644)
	if err != nil {
		return controls, err
	}
	return controls, nil
}

func GenerateSCFMarkdown(scfControl Control, scfControlID SCFControlID, controlMapping ControlMapping) error {
	f, err := os.Create(fmt.Sprintf("docs/scf/%s.md", safeFileName(string(scfControlID))))
	if err != nil {
		return err
	}

	doc := md.NewMarkdown(f).
		H1(fmt.Sprintf("SCF - %s", string(scfControlID))).
		PlainText(string(scfControl[SCFColumnMapping[Description]])).
		H2("Mapped framework controls")

	orderedFrameworks := []string{}
	for framework, _ := range controlMapping {
		orderedFrameworks = append(orderedFrameworks, string(framework))
	}
	slices.Sort(orderedFrameworks)
	for _, framework := range orderedFrameworks {
		frameworkControlIDs := controlMapping[Framework(framework)]
		fcids := []string{}
		for _, fcid := range frameworkControlIDs {
			link := fmt.Sprintf("[%s](../%s/%s.md)", string(fcid), safeFileName(string(framework)), safeFileName(string(fcid)))
			if framework == "GDPR" {
				articleParts := strings.Split(string(fcid), ".")
				if len(articleParts) == 2 {
					subArticle := strings.ReplaceAll(string(fcid), "Art", "Article")
					subArticle = strings.ReplaceAll(subArticle, ".", "")
					subArticle = strings.ReplaceAll(subArticle, " ", "-")
					link = fmt.Sprintf("[%s](../%s/%s.md#%s)", string(fcid), safeFileName(string(framework)), safeFileName(articleParts[0]), url.QueryEscape(subArticle))
				}
			} else if framework == "ISO 27001" || framework == "ISO 27002" {
				annex := FCIDToAnnex(Framework(framework), string(fcid))
				if strings.HasPrefix(annex, "A") {
					annexParts := strings.Split(annex, ".")
					annexLink := fmt.Sprintf("a-%s", annexParts[1])
					annexTarget := safeFileName(annex)
					link = fmt.Sprintf("[%s](../%s/%s.md#%s)", annex, safeFileName(framework), annexLink, annexTarget)
				} else {
					requirementParts := strings.Split(annex, ".")
					requirementLink := fmt.Sprintf("%s", requirementParts[0])
					requirementTarget := safeFileName(annex)
					link = fmt.Sprintf("[%s](../%s/%s.md#%s)", annex, safeFileName(framework), requirementLink, requirementTarget)
				}
			} else if framework == "NIST 800-53" {
				toLink := strings.ReplaceAll(strings.ReplaceAll(string(fcid), ")", ""), "(", "-")
				link = fmt.Sprintf("[%s](../nist80053/%s.md)", string(fcid), safeFileName(toLink))
			}
			found := false
			for _, fcid := range fcids {
				if fcid == link {
					found = true
				}
			}
			if !found {
				fcids = append(fcids, link)
			}

		}
		if len(fcids) > 0 {
			slices.Sort(fcids)
			doc.H3(string(framework)).
				BulletList(fcids...).
				LF()
		}
	}

	doc.H2("Control questions").
		PlainText(string(scfControl[SCFColumnMapping[ControlQuestions]])).
		LF()
	// H2("Control maturity").
	// Table(md.TableSet{
	// 	Header: []string{"Maturity level", "Description"},
	// 	Rows: [][]string{
	// 		{"Not performed", fixControlQuestions(string(scfControl[SCFColumnMapping[NotPerformed]]))},
	// 		{"Performed internally", fixControlQuestions(string(scfControl[SCFColumnMapping[PerformedInternally]]))},
	// 		{"Planned and tracked", fixControlQuestions(string(scfControl[SCFColumnMapping[PlannedAndTracked]]))},
	// 		{"Well defined", fixControlQuestions(string(scfControl[SCFColumnMapping[WellDefined]]))},
	// 		{"Quantitatively controllled", fixControlQuestions(string(scfControl[SCFColumnMapping[QuantitativelyControlled]]))},
	// 		{"Continuously improving", fixControlQuestions(string(scfControl[SCFColumnMapping[ContinuouslyImproving]]))},
	// 	},
	// })
	doc.Build()
	return nil
}

func fixControlQuestions(input string) string {
	return strings.ReplaceAll(strings.ReplaceAll(input, "•	", "- "), "\n", "<br>")
}

func GetComplianceControlMappings(controls SCFControls, soc2Framework *SOC2Framework) SCFControlMappings {
	controlMappings := map[SCFControlID]ControlMapping{}
	for controlID, control := range controls {
		controlMapping := ControlMapping{}
		for framework, header := range SupportedFrameworks {
			fcids := strings.Split(string(control[header]), "\n")
			frameworkControlIDs := []FrameworkControlID{}
			for _, fcid := range fcids {
				// For SOC 2, expand parent control IDs (e.g., P1.0 -> P1.1, P1.2, etc.)
				if framework == "SOC 2" && soc2Framework != nil {
					expandedIDs := soc2Framework.ExpandParentControlID(fcid)
					for _, expandedID := range expandedIDs {
						frameworkControlIDs = append(frameworkControlIDs, FrameworkControlID(expandedID))
					}
				} else {
					frameworkControlIDs = append(frameworkControlIDs, FrameworkControlID(fcid))
				}
			}
			controlMapping[framework] = frameworkControlIDs
			if len(controlMapping[framework]) == 1 && controlMapping[framework][0] == "" {
				controlMapping[framework] = []FrameworkControlID{}
			}
		}
		if controlMapping.MapsToControls() {
			controlMappings[controlID] = controlMapping
		}
	}
	return controlMappings
}

func GenerateSCFIndex(scfControlMappings SCFControlMappings, scfControls SCFControls) error {
	f, err := os.Create("docs/scf/index.md")
	if err != nil {
		return err
	}
	doc := md.NewMarkdown(f).
		H1("SCF Controls")

	controlIDs := []string{}
	for scfControlID, _ := range scfControlMappings {
		controlIDs = append(controlIDs, string(scfControlID))
	}
	slices.Sort(controlIDs)
	controlLinks := []string{}
	lastControlFamily := ""
	for _, controlID := range controlIDs {
		family := ""
		for fam, _ := range SCFControlFamilyMapping {
			if strings.HasPrefix(controlID, fam) {
				family = fam
			}
		}
		if family != lastControlFamily {
			if lastControlFamily != "" {
				doc.BulletList(controlLinks...)
			}
			lastControlFamily = family
			doc.H2(fmt.Sprintf("%s - %s", family, SCFControlFamilyMapping[family]))
			controlLinks = []string{fmt.Sprintf("[%s](%s.md)", controlID, safeFileName(string(controlID)))}
		} else {
			controlLinks = append(controlLinks, fmt.Sprintf("[%s](%s.md)", controlID, safeFileName(string(controlID))))
		}
	}
	doc.Build()
	return nil
}

func GenerateSCFProboImportJson(scfControlMappings SCFControlMappings, scfControls SCFControls) error {
	type ProboControl struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	type ProboImport struct {
		Name     string         `json:"name"`
		ID       string         `json:"id"`
		Controls []ProboControl `json:"controls"`
	}

	var controls []ProboControl
	for scfControlID, _ := range scfControlMappings {
		controlName := strings.Split(string(scfControlID), " - ")
		controls = append(controls, ProboControl{
			ID:   string(scfControlID),
			Name: controlName[1],
		})
	}
	proboImport := ProboImport{
		Name:     "Secure Controls Framework (SCF) 2023.4",
		ID:       "SCF",
		Controls: controls,
	}
	file, err := json.MarshalIndent(proboImport, "", " ")
	if err != nil {
		return err
	}
	err = os.WriteFile("docs/scf/probo-import.json", file, 0644)
	if err != nil {
		return err
	}
	return nil
}

func GenerateSCFProboMeasuresImportJson(scfControlMappings SCFControlMappings, scfControls SCFControls) error {
	type RequestedEvidence struct {
		ReferenceID string `json:"reference-id"`
		Type        string `json:"type"`
		Name        string `json:"name"`
	}
	type Task struct {
		Name               string              `json:"name"`
		Description        string              `json:"description"`
		ReferenceID        string              `json:"reference-id"`
		RequestedEvidences []RequestedEvidence `json:"requested-evidences"`
	}
	type Standard struct {
		Framework string `json:"framework"`
		Control   string `json:"control"`
	}
	type Measure struct {
		Name        string     `json:"name"`
		Category    string     `json:"category"`
		ReferenceID string     `json:"reference-id"`
		Standards   []Standard `json:"standards"`
		Tasks       []Task     `json:"tasks"`
	}

	// Map framework names to their probo-import IDs
	frameworkIDMapping := map[Framework]string{
		"SOC 2":     "SOC2",
		"GDPR":      "GDPR",
		"ISO 27001": "ISO27001",
		"ISO 27002": "ISO27002",
	}

	// Function to convert SCF control IDs to probo-import format
	convertControlID := func(framework Framework, controlID string) string {
		if framework == "ISO 27001" {
			// Convert parentheses to dots: "7.3(a)" -> "7.3.a"
			controlID = strings.ReplaceAll(controlID, "(", ".")
			controlID = strings.ReplaceAll(controlID, ")", "")
			return controlID
		} else if framework == "ISO 27002" {
			// Add "A." prefix if not already present: "5.4" -> "A.5.4"
			if !strings.HasPrefix(controlID, "A") && !strings.HasPrefix(controlID, "a") {
				controlID = "A." + controlID
			}
			return controlID
		} else if framework == "GDPR" {
			// Normalize to 'Article X' or 'Article X.Y' format
			controlID = strings.TrimSpace(controlID)
			controlID = strings.ReplaceAll(controlID, "Art", "Article ")
			controlID = strings.ReplaceAll(controlID, "Article icle", "Article") // handle double replacement
			controlID = strings.ReplaceAll(controlID, "  ", " ")                 // remove double spaces
			controlID = strings.ReplaceAll(controlID, "-", ".")                  // convert dashes to dots if present
			controlID = strings.ReplaceAll(controlID, "..", ".")                 // fix double dots
			controlID = strings.TrimSpace(controlID)
			return controlID
		}
		return controlID
	}

	var measures []Measure
	for scfControlID, controlMapping := range scfControlMappings {
		controlName := strings.Split(string(scfControlID), " - ")
		name := controlName[1]

		// Determine category from control family
		category := ""
		for fam, famName := range SCFControlFamilyMapping {
			if strings.HasPrefix(string(scfControlID), fam) {
				category = famName
				break
			}
		}

		// Build standards array from control mappings
		var standards []Standard
		for framework, frameworkControlIDs := range controlMapping {
			for _, fcid := range frameworkControlIDs {
				if string(fcid) != "" {
					// Use the mapped framework ID instead of the full name
					frameworkID := frameworkIDMapping[framework]
					if frameworkID == "" {
						frameworkID = string(framework) // fallback to original name
					}
					// Convert the control ID to match probo-import format
					convertedControlID := convertControlID(framework, string(fcid))
					standards = append(standards, Standard{
						Framework: frameworkID,
						Control:   convertedControlID,
					})
				}
			}
		}

		// Create a task based on the control questions
		var tasks []Task
		controlQuestions := string(scfControls[scfControlID][SCFColumnMapping[ControlQuestions]])
		if controlQuestions != "" {
			tasks = append(tasks, Task{
				Name:               name,
				Description:        controlQuestions,
				ReferenceID:        string(scfControlID),
				RequestedEvidences: []RequestedEvidence{},
			})
		}

		measure := Measure{
			Name:        name,
			Category:    category,
			ReferenceID: string(scfControlID),
			Standards:   standards,
			Tasks:       tasks,
		}
		measures = append(measures, measure)
	}

	// Export directly as array, not wrapped in object
	file, err := json.MarshalIndent(measures, "", " ")
	if err != nil {
		return err
	}
	err = os.WriteFile("docs/scf/probo-measures-import.json", file, 0644)
	if err != nil {
		return err
	}
	return nil
}

var BadCharacters = []string{
	"../",
	"<!--",
	"-->",
	"<",
	">",
	"'",
	"\"",
	"/",
	"&",
	"$",
	"#",
	"{", "}", "[", "]", "=",
	";", "?", "%20", "%22",
	"%3c", // <
	"%253",
}
