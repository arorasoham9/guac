package identifier

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/guacsec/guac/pkg/assembler/helpers"
	"github.com/jedib0t/go-pretty/v6/table"
)

type HardID struct {
	ID          string         `json:"id"`
	ArtifactIDs []ArtifactID   `json:"artifact_ids"`
	Counts      map[string]int `json:"counts"`
}

type GUACIDPool struct {
	IDs      map[string]*GUACIDNode `json:"ids"`
	IDsInUse map[string]int         `json:"ids_in_use"`
}

type ArtifactID struct {
	Nodes []*GUACIDNode `json:"nodes"`
}

type GUACIDNode struct {
	Property string  `json:"property"`
	Value    string  `json:"value"`
	Hardness float32 `json:"hardness"`
}

type Component struct {
	Name string            `json:"name,omitempty"`
	Purl string            `json:"purl,omitempty"`
	Swid map[string]string `json:"swid,omitempty"`
	Cpe  string            `json:"cpe,omitempty"`
	ID   HardID
}

type SBOM struct {
	SerialNumber string      `json:"serialNumber"`
	Components   []Component `json:"components"`
}

type IdentifiedSBOMs struct {
	Sboms  []SBOM
	IDPool GUACIDPool
}

func NewHardID(id string) HardID {
	return HardID{
		ID:          id,
		ArtifactIDs: []ArtifactID{},       // Initializes an empty slice of ArtifactIDs
		Counts:      make(map[string]int), // Initializes the Counts map
	}
}

func NewGUACIDPool() GUACIDPool {
	return GUACIDPool{
		IDs:      make(map[string]*GUACIDNode), // Initializes the IDs map
		IDsInUse: make(map[string]int),         // Initializes the IDsInUse map
	}
}

func ProcessSBOMFilesInDirectory(dirPath string) ([]SBOM, error) {
	var sboms []SBOM
	err := filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if !info.IsDir() {
			sbom, err := ReadCycloneDXSBOMFromFile(path)
			if err != nil {
				return err
			}
			sboms = append(sboms, sbom)
		}

		return nil
	})

	if err != nil {
		return sboms, fmt.Errorf("error walking the path %q: %v", dirPath, err)
	}
	return sboms, nil
}

func ReadCycloneDXSBOMFromFile(filePath string) (SBOM, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return SBOM{}, fmt.Errorf("error reading file: %v", err)
	}

	var sbom SBOM
	err = json.Unmarshal(data, &sbom)
	if err != nil {
		return SBOM{}, fmt.Errorf("error unmarshalling JSON: %v", err)
	}
	return sbom, nil
}

// Function to parse PURL strings
func ParsePurl(purlUri string) (map[string]string, error) {
	pkg, err := helpers.PurlToPkg(purlUri)
	if err != nil {
		return nil, fmt.Errorf("unable to parse purl %s: %v", purlUri, err)
	}
	parsed := make(map[string]string)
	parsed["name"] = pkg.GetName()
	parsed["namespace"] = *pkg.GetNamespace()
	parsed["subpath"] = *pkg.GetSubpath()
	parsed["type"] = pkg.GetType()
	parsed["version"] = *pkg.GetVersion()

	for _, qualifier := range pkg.Qualifiers {
		parsed[qualifier.Key] = qualifier.Value
	}

	return parsed, nil

}

// Function to parse CPE strings
// CPE Format
//
//cpe:2.3:<part>:<vendor>:<product>:<version>:<update>:<edition>:<language>:<sw_edition>:<target_sw>:<target_hw>:<other>:<platform>
func ParseCpe(cpe string) map[string]string {
	parsed := make(map[string]string)

	// Remove the "cpe:2.3:" prefix
	cpe = strings.TrimPrefix(cpe, "cpe:2.3:")

	// Split the CPE string into components
	components := strings.Split(cpe, ":")

	// Assign components based on their positions
	if len(components) > 0 && components[0] != "*" {
	
		parsed["part"] = components[0]
	}
	if len(components) > 1 && components[1] != "*"{
		parsed["vendor"] = components[1]
	}
	if len(components) > 2 && components[2] != "*"{
		parsed["product"] = components[2]
	}
	if len(components) > 3 && components[3] != "*"{
		parsed["version"] = components[3]
	}
	if len(components) > 4 && components[4] != "*"{
		parsed["update"] = components[4]
	}
	if len(components) > 5 && components[5] != "*" {
		parsed["edition"] = components[5]
	}
	if len(components) > 6 && components[6] != "*"{
		parsed["language"] = components[6]
	}
	if len(components) > 7 && components[7] != "*"{
		parsed["sw_edition"] = components[7]
	}
	if len(components) > 8 && components[8] != "*"{
		parsed["target_sw"] = components[8]
	}
	if len(components) > 9 && components[9] != "*"{
		parsed["target_hw"] = components[9]
	}
	if len(components) > 10 && components[10] != "*"{
		parsed["other"] = components[10]
	}

	return parsed
}

func ComputeArtifactID(labels map[string]string, pool *GUACIDPool, counts *map[string]int) ArtifactID {

	var artifactID ArtifactID

	for key, value := range labels {

		if _, ok := pool.IDs[key+value]; !ok {
			pool.IDs[key+value] = &GUACIDNode{
				Property: key,
				Value:    value,
				Hardness: 0, //how is this computed?
			}
		}
		pool.IDsInUse[key+value] += 1
		if _, ok := (*counts)[key+value]; !ok {
			(*counts)[key+value] = 0
		}
		(*counts)[key+value] = (*counts)[key+value] + 1
		artifactID.Nodes = append(artifactID.Nodes, pool.IDs[key+value])
	}
	return artifactID
}
func IdMismatch(ids []ArtifactID) {
	// Check if the list is empty or has only one element (no mismatch possible)
	if len(ids) <= 1 {
		// fmt.Println("No mismatch: Only one or no ArtifactID provided.")
		return
	}

	// Helper function to create a map from property -> value for each ArtifactID
	buildPropertyMap := func(artifactID ArtifactID) map[string]string {
		propertyMap := make(map[string]string)
		for _, node := range artifactID.Nodes {
			propertyMap[node.Property] = node.Value
		}
		return propertyMap
	}

	// Use the first ArtifactID's properties as the reference
	referenceMap := buildPropertyMap(ids[0])

	// Iterate over the rest of the ArtifactIDs
	for i := 1; i < len(ids); i++ {
		artifactID := ids[i]
		currentMap := buildPropertyMap(artifactID)

		// Compare the current ArtifactID's properties against the reference
		for prop, refValue := range referenceMap {
			currentValue, exists := currentMap[prop]
			if !exists {
				// Property missing in current ArtifactID
				// fmt.Printf("Mismatch found in ArtifactID[%d]: Missing property '%s'\n", i, prop)
				// os.Exit(1)
				continue
			}

			// Check if the value is the same for the property
			if refValue != currentValue {
				fmt.Printf("Mismatch found in ArtifactID[%d]: Property '%s' value mismatch. Expected: %s, Found: %s\n",
					i, prop, refValue, currentValue)
				os.Exit(1)
			}
		}

		// Check if current ArtifactID has extra properties not in the reference
		// for prop := range currentMap {
		// 	if _, exists := referenceMap[prop]; !exists {
		// 		fmt.Printf("Mismatch found in ArtifactID[%d]: Extra property '%s' not present in the reference ArtifactID\n", i, prop)
		// 		os.Exit(1)
		// 	}
		// }
	}

}

func ProcessIDsFromSBOMs(sboms []SBOM) (IdentifiedSBOMs, error) {

	var identifiedSBOMs IdentifiedSBOMs
	var guacIdPool = NewGUACIDPool()

	counts := make(map[string]int)
	for i, sbom := range sboms {
		for j, component := range sbom.Components {
			var hardID = NewHardID("")
			hardID.ID = component.Name
			if component.Purl != "" {
				purlDict, err := ParsePurl(component.Purl)
				if err != nil {
					return identifiedSBOMs, fmt.Errorf("could not parse PURL %v", component.Purl)
				}
				id := ComputeArtifactID(purlDict, &guacIdPool, &counts)
				hardID.ArtifactIDs = append(hardID.ArtifactIDs, id)
			}

			if component.Cpe != "" {
				cpeDict := ParseCpe(component.Cpe)
				id := ComputeArtifactID(cpeDict, &guacIdPool, &counts)
				hardID.ArtifactIDs = append(hardID.ArtifactIDs, id)
			}

			if len(component.Swid) != 0 {
				id := ComputeArtifactID(component.Swid, &guacIdPool, &counts)
				hardID.ArtifactIDs = append(hardID.ArtifactIDs, id)
			}

			IdMismatch(hardID.ArtifactIDs) 
	
			

			hardID.Counts = counts
			//add hardId to component
			sboms[i].Components[j].ID = hardID
		}
	}

	identifiedSBOMs.Sboms = sboms
	identifiedSBOMs.IDPool = guacIdPool

	return identifiedSBOMs, nil
}
func FindArtifactConflicts(identifiedSBOMs IdentifiedSBOMs) {
	// Map to store components by their HardID.ID
	hardIDMap := make(map[string][]Component)

	// Iterate over all SBOMs
	for _, sbom := range identifiedSBOMs.Sboms {
		// Iterate over all components in the SBOM
		for _, component := range sbom.Components {
			// Group components by HardID.ID
			hardID := component.ID.ID
			hardIDMap[hardID] = append(hardIDMap[hardID], component)
		}
	}

	// Prepare table to show conflicts
	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	t.SetStyle(table.StyleColoredBright)
	// t.AppendHeader(table.Row{"HardID", "SBOM Serial Numbers", "Conflicting ArtifactIDs", "Conflict Details"})
	t.AppendHeader(table.Row{"HardID", "Conflicting Artifact(s)"})
	// Now we have all components grouped by their HardID.ID
	// We need to check for conflicts in ArtifactIDs
	for hardID, components := range hardIDMap {
		if len(components) > 1 {
			artifactIDMap := make(map[string]map[string]bool) // ArtifactID key -> map of SBOM serial numbers
			conflictDetails := make(map[string][]string)      // To store conflicting details
			conflictFound := false

			// Check ArtifactIDs for conflicts
			for _, component := range components {
				sbomSerial := findSBOMSerialNumber(identifiedSBOMs.Sboms, component)
				for _, artifactID := range component.ID.ArtifactIDs {
					artifactIDKey := artifactIDKey(artifactID) // Helper function to generate a unique key for ArtifactID

					if _, exists := artifactIDMap[artifactIDKey]; !exists {
						artifactIDMap[artifactIDKey] = map[string]bool{sbomSerial: true}
					} else {
						artifactIDMap[artifactIDKey][sbomSerial] = true
						conflictFound = true
					}

					// Collect details for this artifact's nodes
					conflictDetails[artifactIDKey] = append(conflictDetails[artifactIDKey], formatArtifactDetails(artifactID))
				}
			}

			// If conflict found, prepare the data for the table
			if conflictFound {
				// sbomSerials := collectSBOMSerials(artifactIDMap)
				conflictingArtifactIDs := collectConflictingArtifactIDs(artifactIDMap)
				// conflictDescription := formatConflictDetails(conflictDetails)

				t.AppendRow(table.Row{
					hardID,
					// sbomSerials,
					conflictingArtifactIDs,
					// conflictDescription,
				})
			}
		}
	}

	// Render the table
	t.Render()
}

// Helper function to generate a unique key for ArtifactID (based on its nodes)
func artifactIDKey(artifactID ArtifactID) string {
	key := ""
	for _, node := range artifactID.Nodes {
		key += fmt.Sprintf("%s:%s:%f-", node.Property, node.Value, node.Hardness)
	}
	return key
}

// Helper function to find the SBOM serial number based on the component
func findSBOMSerialNumber(sboms []SBOM, component Component) string {

	for _, sbom := range sboms {
		for _, sbomComponent := range sbom.Components {
			if sbomComponent.ID.ID == component.ID.ID {
				return sbom.SerialNumber
			}
		}
	}
	return "unknown"
}

// Helper function to collect SBOM serial numbers for conflicting ArtifactIDs
func CollectSBOMSerials(artifactIDMap map[string]map[string]bool) string {
	serials := make(map[string]bool)
	for _, sbomSerials := range artifactIDMap {
		for sbomSerial := range sbomSerials {
			serials[sbomSerial] = true
		}
	}
	result := ""
	for serial := range serials {
		result += serial + ", "
	}
	return result[:len(result)-2] // Trim the last ", "
}

// Helper function to collect conflicting ArtifactIDs for display
func collectConflictingArtifactIDs(artifactIDMap map[string]map[string]bool) string {
	ids := ""
	for artifactID := range artifactIDMap {
		ids += artifactID + "\n"
		return ids
	}
	return ids
}

// Helper function to format the conflict details (artifact node information)
func FormatConflictDetails(conflictDetails map[string][]string) string {
	details := ""
	for artifactID, nodes := range conflictDetails {
		details += fmt.Sprintf("ArtifactID: %s\n", artifactID)
		for _, nodeDetail := range nodes {
			details += fmt.Sprintf("  - %s\n", nodeDetail)
		}
		details += "\n"
	}
	return details
}

// Helper function to format ArtifactID node details
func formatArtifactDetails(artifactID ArtifactID) string {
	detail := ""
	for _, node := range artifactID.Nodes {
		detail += fmt.Sprintf("Node(Property: %s, Value: %s, Hardness: %f)", node.Property, node.Value, node.Hardness)
	}
	return detail
}
