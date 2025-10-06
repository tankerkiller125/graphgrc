package internal

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"slices"
	"strings"

	md "github.com/go-spectest/markdown"
)

type ParsedDescription struct {
	Header string
	Body   string
}

type PointOfFocus struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	Requirement string `json:"requirement"`
}

type SOC2Control struct {
	ID        string         `json:"id"`
	Principle string         `json:"principle"`
	POF       []PointOfFocus `json:"pof"`
}

type TrustServicesCriteria struct {
	ControlEnvironment               []SOC2Control `json:"controlEnvironment"`
	InformationAndCommunication      []SOC2Control `json:"informationAndCommunication"`
	RiskAssessment                   []SOC2Control `json:"riskAssessment"`
	MonitoringActivities             []SOC2Control `json:"monitoringActivities"`
	ControlActivities                []SOC2Control `json:"controlActivities"`
	LogicalAndPhysicalAccessControls []SOC2Control `json:"logicalAndPhysicalAccessControls"`
	SystemOperations                 []SOC2Control `json:"systemOperations"`
	ChangeManagement                 []SOC2Control `json:"changeManagement"`
	RiskMitigation                   []SOC2Control `json:"riskMitigation"`
	AdditionalCriteria               struct {
		Availability    []SOC2Control `json:"availability"`
		Confidentiality []SOC2Control `json:"confidentiality"`
		Privacy         []SOC2Control `json:"privacy"`
	} `json:"additionalCriteria"`
}

type SOC2Framework struct {
	TrustServicesCriteria TrustServicesCriteria `json:"trustServicesCriteria"`
}

// Legacy types for compatibility
type Requirement struct {
	ID          string `json:"Id"`
	Name        string `json:"Name"`
	Description string `json:"Description"`
	Attributes  []struct {
		ItemID  string `json:"ItemId"`
		Section string `json:"Section"`
		Service string `json:"Service"`
		Type    string `json:"Type"`
	} `json:"Attributes"`
}

type FrameworkSummary struct {
	Framework    string        `json:"Framework"`
	Version      string        `json:"Version"`
	Provider     string        `json:"Provider"`
	Description  string        `json:"Description"`
	Requirements []Requirement `json:"Requirements"`
}

func GetSOC2Controls(url string, getFile bool) (SOC2Framework, error) {
	framework := SOC2Framework{}
	if getFile {
		resp, err := http.Get(url)
		if err != nil {
			return framework, err
		}
		defer resp.Body.Close()
		out, err := os.Create("soc2.json")
		if err != nil {
			return framework, err
		}
		defer out.Close()
		io.Copy(out, resp.Body)
	}
	soc2File, err := os.Open("soc2.json")
	if err != nil {
		return framework, err
	}
	defer soc2File.Close()
	soc2Bytes, err := io.ReadAll(soc2File)
	if err != nil {
		return framework, err
	}
	if err := json.Unmarshal(soc2Bytes, &framework); err != nil {
		return framework, err
	}
	return framework, nil
}

// GetAllControls returns a flat list of all controls across all categories
func (f *SOC2Framework) GetAllControls() []SOC2Control {
	var allControls []SOC2Control
	allControls = append(allControls, f.TrustServicesCriteria.ControlEnvironment...)
	allControls = append(allControls, f.TrustServicesCriteria.InformationAndCommunication...)
	allControls = append(allControls, f.TrustServicesCriteria.RiskAssessment...)
	allControls = append(allControls, f.TrustServicesCriteria.MonitoringActivities...)
	allControls = append(allControls, f.TrustServicesCriteria.ControlActivities...)
	allControls = append(allControls, f.TrustServicesCriteria.LogicalAndPhysicalAccessControls...)
	allControls = append(allControls, f.TrustServicesCriteria.SystemOperations...)
	allControls = append(allControls, f.TrustServicesCriteria.ChangeManagement...)
	allControls = append(allControls, f.TrustServicesCriteria.RiskMitigation...)
	allControls = append(allControls, f.TrustServicesCriteria.AdditionalCriteria.Availability...)
	allControls = append(allControls, f.TrustServicesCriteria.AdditionalCriteria.Confidentiality...)
	allControls = append(allControls, f.TrustServicesCriteria.AdditionalCriteria.Privacy...)
	return allControls
}

// ExpandParentControlID expands a parent control ID (e.g., "P1.0") to all its child control IDs (e.g., ["P1.1", "P1.2"])
// If the ID doesn't end in .0, it returns the original ID
func (f *SOC2Framework) ExpandParentControlID(controlID string) []string {
	// If it doesn't end in .0, it's not a parent ID
	if !strings.HasSuffix(controlID, ".0") {
		return []string{controlID}
	}

	// Extract the prefix (e.g., "P1" from "P1.0")
	prefix := strings.TrimSuffix(controlID, ".0")

	// Find all controls that start with this prefix
	var expandedIDs []string
	for _, control := range f.GetAllControls() {
		if strings.HasPrefix(control.ID, prefix+".") && control.ID != controlID {
			expandedIDs = append(expandedIDs, control.ID)
		}
	}

	// If we found children, return them; otherwise return the original ID
	if len(expandedIDs) > 0 {
		return expandedIDs
	}
	return []string{controlID}
}

// Thanks ChatGPT
func getFirstWord(input string) string {
	words := strings.Fields(input)
	if len(words) > 0 {
		return words[0]
	}
	return ""
}

func GenerateSOC2Markdown(control SOC2Control, scfControlMapping SCFControlMappings) error {
	id := strings.ToLower(strings.ReplaceAll(control.ID, ".", "-"))
	f, err := os.Create(fmt.Sprintf("docs/soc2/%s.md", safeFileName(id)))
	if err != nil {
		return err
	}
	defer f.Close()

	doc := md.NewMarkdown(f).
		H1(fmt.Sprintf("SOC2 - %s", control.ID)).
		H2("Principle").
		PlainText(control.Principle)

	if len(control.POF) > 0 {
		doc.H2("Points of Focus")
		for _, pof := range control.POF {
			doc.H3(fmt.Sprintf("%s: %s", pof.ID, pof.Title)).
				PlainText(pof.Requirement)
		}
	}

	doc.H2("Mapped SCF controls")
	fcids := []string{}
	for scfID, controlMapping := range scfControlMapping {
		soc2FrameworkControlIDs := controlMapping["SOC 2"]
		for _, fcid := range soc2FrameworkControlIDs {
			if string(fcid) == control.ID {
				fcids = append(fcids, fmt.Sprintf("[%s](../scf/%s.md)", string(scfID), safeFileName(string(scfID))))
			}
		}
	}
	slices.Sort(fcids)
	if len(fcids) > 0 {
		doc.BulletList(fcids...)
	} else {
		doc.PlainText("No mapped SCF controls found.")
	}
	doc.Build()
	return nil
}

func GenerateSOC2Index(soc2Framework SOC2Framework) error {
	f, err := os.Create("docs/soc2/index.md")
	if err != nil {
		return err
	}
	defer f.Close()

	doc := md.NewMarkdown(f).H1("SOC2 Controls")

	categories := []struct {
		name     string
		controls []SOC2Control
	}{
		{"Control Environment", soc2Framework.TrustServicesCriteria.ControlEnvironment},
		{"Information and Communication", soc2Framework.TrustServicesCriteria.InformationAndCommunication},
		{"Risk Assessment", soc2Framework.TrustServicesCriteria.RiskAssessment},
		{"Monitoring Activities", soc2Framework.TrustServicesCriteria.MonitoringActivities},
		{"Control Activities", soc2Framework.TrustServicesCriteria.ControlActivities},
		{"Logical and Physical Access Controls", soc2Framework.TrustServicesCriteria.LogicalAndPhysicalAccessControls},
		{"System Operations", soc2Framework.TrustServicesCriteria.SystemOperations},
		{"Change Management", soc2Framework.TrustServicesCriteria.ChangeManagement},
		{"Risk Mitigation", soc2Framework.TrustServicesCriteria.RiskMitigation},
		{"Additional Criteria", soc2Framework.TrustServicesCriteria.AdditionalCriteria.Availability},
		{"Additional Criteria", soc2Framework.TrustServicesCriteria.AdditionalCriteria.Confidentiality},
		{"Additional Criteria", soc2Framework.TrustServicesCriteria.AdditionalCriteria.Privacy},
	}

	for _, category := range categories {
		if len(category.controls) > 0 {
			doc.H2(category.name)
			var controlLinks []string
			for _, control := range category.controls {
				id := strings.ToLower(strings.ReplaceAll(control.ID, ".", "-"))
				controlLinks = append(controlLinks, fmt.Sprintf("[%s](%s.md)", control.ID, safeFileName(id)))
			}
			doc.BulletList(controlLinks...)
		}
	}

	doc.Build()
	return nil
}

func GenerateSOC2ProboImportJson(soc2Framework SOC2Framework) error {
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
	allControls := soc2Framework.GetAllControls()
	for _, control := range allControls {
		controls = append(controls, ProboControl{
			ID:   control.ID,
			Name: control.Principle,
		})
	}

	proboImport := ProboImport{
		Name:     "SOC 2",
		ID:       "SOC2",
		Controls: controls,
	}

	data, err := json.MarshalIndent(proboImport, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile("docs/soc2/probo-import.json", data, 0644)
}
