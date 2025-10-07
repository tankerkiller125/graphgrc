package main

import (
	"log"

	"github.com/alsmola/graphgrc/internal"
)

func main() {
	// todo initialize flags
	latestScfLink := "https://github.com/securecontrolsframework/securecontrolsframework/raw/refs/heads/main/Archived%20Versions/SCF-2023/Secure%20Controls%20Framework%20(SCF)%20-%202023.4.xlsx"
	//getFile := false
	scfControls, err := internal.ReturnSCFControls(latestScfLink, true)
	if err != nil {
		log.Fatal(err)
	}

	soc2Link := "https://raw.githubusercontent.com/CyberRiskGuy/aicpa-soc-tsc-json/refs/heads/main/trust-services-criteria/2017-trust-services-criteria-with-revised-points-of-focus-2022.controls.json"
	soc2Framework, err := internal.GetSOC2Controls(soc2Link, true)
	if err != nil {
		log.Fatal(err)
	}

	scfControlMappings := internal.GetComplianceControlMappings(scfControls, &soc2Framework)
	for scfControlID, controlMapping := range scfControlMappings {
		internal.GenerateSCFMarkdown(scfControls[scfControlID], scfControlID, controlMapping)
	}
	internal.GenerateSCFProboImportJson(scfControlMappings, scfControls)
	internal.GenerateSCFProboMeasuresImportJson(scfControlMappings, scfControls)
	internal.GenerateSCFIndex(scfControlMappings, scfControls)

	allControls := soc2Framework.GetAllControls()
	for _, control := range allControls {
		err = internal.GenerateSOC2Markdown(control, scfControlMappings)
		if err != nil {
			log.Fatal(err)
		}
	}
	internal.GenerateSOC2ProboImportJson(soc2Framework)
	internal.GenerateSOC2Index(soc2Framework)

	gdprLink := "https://raw.githubusercontent.com/enterpriseready/enterpriseready/master/content/gdpr/gdpr-abridged.md"
	gdprFramework, err := internal.GetGDPRControls(gdprLink, true)
	if err != nil {
		log.Fatal(err)
	}
	for _, article := range gdprFramework {
		if article.Title != "" {
			err = internal.GenerateGDPRMarkdown(article, scfControlMappings)
			if err != nil {
				log.Fatal(err)
			}
		}

	}
	internal.GenerateGDPRProboImportJson(gdprFramework)
	internal.GenerateGDPRIndex(gdprFramework)

	iso27001 := internal.Framework("ISO 27001")
	iso27002 := internal.Framework("ISO 27002")

	iso27001Link := "https://raw.githubusercontent.com/JupiterOne/security-policy-templates/main/templates/standards/iso-iec-27001-2022.json"
	iso27001Framework, err := internal.GetISOControls(iso27001, iso27001Link, true)
	if err != nil {
		log.Fatal(err)
	}
	for _, domain := range iso27001Framework.Domains {
		err = internal.GenerateISOMarkdown(iso27001, domain, scfControlMappings)
		if err != nil {
			log.Fatal(err)
		}
	}
	internal.GenerateISOProboImportJson(iso27001, iso27001Framework)
	internal.GenerateISOIndex(iso27001, iso27001Framework)

	iso27002Link := "https://raw.githubusercontent.com/JupiterOne/security-policy-templates/main/templates/standards/iso-27002-2022.json"
	iso27002Framework, err := internal.GetISOControls(iso27002, iso27002Link, true)
	if err != nil {
		log.Fatal(err)
	}
	for _, domain := range iso27002Framework.Domains {
		err = internal.GenerateISOMarkdown(iso27002, domain, scfControlMappings)
		if err != nil {
			log.Fatal(err)
		}
	}
	internal.GenerateISOProboImportJson(iso27002, iso27002Framework)
	internal.GenerateISOIndex(iso27002, iso27002Framework)
}
