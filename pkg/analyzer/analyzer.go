//
// Copyright 2024 The GUAC Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package analyzer

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"
	"sort"
	"strings"

	"github.com/Khan/genqlient/graphql"
	"github.com/dominikbraun/graph"
	model "github.com/guacsec/guac/pkg/assembler/clients/generated"
	"github.com/guacsec/guac/pkg/assembler/helpers"
)

type Node struct {
	ID         string
	Message    string
	Attributes map[string]interface{}
	Color      string
}

type DiffedPath struct {
	PathOne []*Node
	PathTwo []*Node
	Diffs   [][]string
}

type packageNameSpaces []model.AllPkgTreeNamespacesPackageNamespace

type packageNameSpacesNames []model.AllPkgTreeNamespacesPackageNamespaceNamesPackageName

type packageNameSpacesNamesVersions []model.AllPkgTreeNamespacesPackageNamespaceNamesPackageNameVersionsPackageVersion

type packageNameSpacesNamesVersionsQualifiers []model.AllPkgTreeNamespacesPackageNamespaceNamesPackageNameVersionsPackageVersionQualifiersPackageQualifier

func (a packageNameSpaces) Len() int           { return len(a) }
func (a packageNameSpaces) Less(i, j int) bool { return a[i].Namespace < a[j].Namespace }
func (a packageNameSpaces) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }

func (a packageNameSpacesNames) Len() int           { return len(a) }
func (a packageNameSpacesNames) Less(i, j int) bool { return a[i].Name < a[j].Name }
func (a packageNameSpacesNames) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }

func (a packageNameSpacesNamesVersions) Len() int           { return len(a) }
func (a packageNameSpacesNamesVersions) Less(i, j int) bool { return a[i].Version < a[j].Version }
func (a packageNameSpacesNamesVersions) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }

func (a packageNameSpacesNamesVersionsQualifiers) Len() int           { return len(a) }
func (a packageNameSpacesNamesVersionsQualifiers) Less(i, j int) bool { return a[i].Key < a[j].Key }
func (a packageNameSpacesNamesVersionsQualifiers) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }

func NodeHash(n *Node) string {
	return n.ID
}

func SetNodeAttribute(g graph.Graph[string, *Node], ID, key string, value interface{}) bool {
	node, err := g.Vertex(ID)
	if err != nil {
		return false
	}

	node.Attributes[key] = value
	return true
}

func GetNodeAttribute(g graph.Graph[string, *Node], ID, key string) (interface{}, error) {
	node, err := g.Vertex(ID)
	if err != nil {
		return nil, err
	}
	val, ok := node.Attributes[key]

	if !ok {
		return ID, nil
	}
	return val, nil
}

func getPkgResponseFromPurl(ctx context.Context, gqlclient graphql.Client, purl string) (*model.PackagesResponse, error) {
	pkgInput, err := helpers.PurlToPkg(purl)
	if err != nil {
		return nil, fmt.Errorf("failed to parse PURL: %v", err)
	}

	pkgQualifierFilter := []model.PackageQualifierSpec{}
	for _, qualifier := range pkgInput.Qualifiers {
		// to prevent https://github.com/golang/go/discussions/56010
		qualifier := qualifier
		pkgQualifierFilter = append(pkgQualifierFilter, model.PackageQualifierSpec{
			Key:   qualifier.Key,
			Value: &qualifier.Value,
		})
	}

	pkgFilter := &model.PkgSpec{
		Type:       &pkgInput.Type,
		Namespace:  pkgInput.Namespace,
		Name:       &pkgInput.Name,
		Version:    pkgInput.Version,
		Subpath:    pkgInput.Subpath,
		Qualifiers: pkgQualifierFilter,
	}
	pkgResponse, err := model.Packages(ctx, gqlclient, *pkgFilter)
	if err != nil {
		return nil, fmt.Errorf("error querying for package: %v", err)
	}
	if len(pkgResponse.Packages) != 1 {
		return nil, fmt.Errorf("failed to located package based on purl")
	}
	return pkgResponse, nil
}

func FindHasSBOMBy(filter model.HasSBOMSpec, uri, purl, id string, ctx context.Context, gqlclient graphql.Client) (*model.HasSBOMsResponse, error) {
	var foundHasSBOMPkg *model.HasSBOMsResponse
	var err error
	if purl != "" {
		pkgResponse, err := getPkgResponseFromPurl(ctx, gqlclient, purl)
		if err != nil {
			return nil, fmt.Errorf("getPkgResponseFromPurl - error: %v", err)
		}
		foundHasSBOMPkg, err = model.HasSBOMs(ctx, gqlclient, model.HasSBOMSpec{Subject: &model.PackageOrArtifactSpec{Package: &model.PkgSpec{Id: &pkgResponse.Packages[0].Namespaces[0].Names[0].Versions[0].Id}}})
		if err != nil {
			return nil, fmt.Errorf("(purl)failed getting hasSBOM with error :%v", err)
		}
	} else if uri != "" {
		foundHasSBOMPkg, err = model.HasSBOMs(ctx, gqlclient, model.HasSBOMSpec{Uri: &uri})
		if err != nil {
			return nil, fmt.Errorf("(uri)failed getting hasSBOM  with error: %v", err)
		}
	} else if id != "" {
		foundHasSBOMPkg, err = model.HasSBOMs(ctx, gqlclient, model.HasSBOMSpec{Id: &id})
		if err != nil {
			return nil, fmt.Errorf("(id)failed getting hasSBOM  with error: %v", err)
		}
	} else {
		foundHasSBOMPkg, err = model.HasSBOMs(ctx, gqlclient, filter)
		if err != nil {
			return nil, fmt.Errorf("(filter)failed getting hasSBOM  with error: %v", err)
		}
	}
	return foundHasSBOMPkg, nil
}

func dfsFindPaths(nodeID string, allNodeEdges map[string]map[string]graph.Edge[string], currentPath []string, allPaths *[][]string) {
	currentPath = append(currentPath, nodeID)

	// Check if the current node has any outgoing edges
	if val, ok := allNodeEdges[nodeID]; ok && len(val) == 0 {
		// If not, add the current path to the list of all paths
		*allPaths = append(*allPaths, currentPath)
		return
	}

	// Iterate over the adjacent nodes of the current node
	for target := range allNodeEdges[nodeID] {
		// Recursively explore the adjacent node
		dfsFindPaths(target, allNodeEdges, currentPath, allPaths)
	}
}

func FindPathsFromHasSBOMNode(g graph.Graph[string, *Node]) ([][]string, error) {

	var paths [][]string
	var currentPath []string
	allNodeEdges, err := g.AdjacencyMap()
	if err != nil {
		return paths, fmt.Errorf("error getting adjacency map")
	}
	if len(allNodeEdges) == 0 {
		return paths, nil
	}
	for nodeID := range allNodeEdges {
		if nodeID == "HasSBOM" {
			continue
		}
		val, err := GetNodeAttribute(g, nodeID, "nodeType")
		if err != nil {
			return paths, fmt.Errorf("error getting node type")
		}
		value, ok := val.(string)
		if !ok {
			return paths, fmt.Errorf("error casting node type to string")
		}
		if value == "Package" {
			//now start dfs
			dfsFindPaths(nodeID, allNodeEdges, currentPath, &paths)
		}
	}
	if len(paths) == 0 && len(allNodeEdges) > 1 {
		return paths, fmt.Errorf("paths 0, nodes > 1")
	}
	return paths, nil
}

func HighlightAnalysis(gOne, gTwo graph.Graph[string, *Node], action int) ([][]*Node, [][]*Node, error) {
	pathsOne, errOne := FindPathsFromHasSBOMNode(gOne)
	pathsTwo, errTwo := FindPathsFromHasSBOMNode(gTwo)
	var analysisOne, analysisTwo [][]*Node
	if errOne != nil || errTwo != nil {
		return analysisOne, analysisTwo, fmt.Errorf("error getting graph paths errOne-%v, errTwo-%v", errOne.Error(), errTwo.Error())
	}

	pathsOneStrings := concatenateLists(pathsOne)
	pathsTwoStrings := concatenateLists(pathsTwo)

	pathsOneMap := make(map[string][]*Node)
	pathsTwoMap := make(map[string][]*Node)

	for i := range pathsOne {
		nodes, err := nodeIDListToNodeList(gOne, pathsOne[i])
		if err != nil {
			return analysisOne, analysisTwo, err
		}
		pathsOneMap[pathsOneStrings[i]] = nodes
	}

	for i := range pathsTwo {
		nodes, err := nodeIDListToNodeList(gTwo, pathsTwo[i])
		if err != nil {
			return analysisOne, analysisTwo, err
		}
		pathsTwoMap[pathsTwoStrings[i]] = nodes

	}

	switch action {
	//0 is diff
	case 0:
		for key, val := range pathsOneMap {
			_, ok := pathsTwoMap[key]
			if !ok {
				//missing
				analysisOne = append(analysisOne, val)
			}
		}

		for key, val := range pathsTwoMap {
			_, ok := pathsOneMap[key]
			if !ok {
				//missing
				analysisTwo = append(analysisTwo, val)
			}
		}

		//do the compare here
	case 1:
		// 1 is intersect
		for key := range pathsOneMap {
			val, ok := pathsTwoMap[key]
			if ok {
				//common
				analysisOne = append(analysisOne, val)
			}
		}
		//do the compare here
	case 2:
		//2 is union
		for _, val := range pathsOneMap {
			analysisOne = append(analysisOne, val)
		}

		for key, val := range pathsTwoMap {
			_, ok := pathsOneMap[key]
			if !ok {
				//common
				analysisTwo = append(analysisTwo, val)
			}
		}
		//do the compare here
	}

	return analysisOne, analysisTwo, nil
}

func MakeGraph(hasSBOM model.HasSBOMsHasSBOM, metadata, inclSoft, inclDeps, inclOccur, namespaces bool) (graph.Graph[string, *Node], error) {

	g := graph.New(NodeHash, graph.Directed())

	//create HasSBOM node
	AddGraphNode(g, "HasSBOM", "black")

	compareAll := !metadata && !inclSoft && !inclDeps && !inclOccur && !namespaces

	if metadata || compareAll {
		//add metadata
		if !(SetNodeAttribute(g, "HasSBOM", "Algorithm", hasSBOM.Algorithm) &&
			SetNodeAttribute(g, "HasSBOM", "Digest", hasSBOM.Digest) &&
			SetNodeAttribute(g, "HasSBOM", "Uri", hasSBOM.Uri)) {
			return g, fmt.Errorf("error setting metadata attribute(s)")
		}
	}
	//TODO: inclSoft and inclOccur

	if inclDeps || compareAll {
		//add included dependencies
		//TODO: sort dependencies as well here
		for _, dependency := range hasSBOM.IncludedDependencies {
			//package node
			//sort namespaces
			sort.Sort(packageNameSpaces(dependency.Package.Namespaces))
			message := dependency.Package.Type
			for _, namespace := range dependency.Package.Namespaces {
				message += namespace.Namespace
				sort.Sort(packageNameSpacesNames(namespace.Names))
				for _, name := range namespace.Names {
					message += name.Name
					sort.Sort(packageNameSpacesNamesVersions(name.Versions))
					for _, version := range name.Versions {
						message += version.Version
						message += version.Subpath
						sort.Sort(packageNameSpacesNamesVersionsQualifiers(version.Qualifiers))
						for _, outlier := range version.Qualifiers {
							message += outlier.Key
							message += outlier.Value
						}
					}
				}
			}

			if message == "" {
				return g, fmt.Errorf("encountered empty message for hashing")
			}

			hashValPackage := nodeHasher([]byte(message))
			_, err := g.Vertex(hashValPackage)

			if err != nil { //node does not exist
				AddGraphNode(g, hashValPackage, "black") // so, create a node
				AddGraphEdge(g, "HasSBOM", hashValPackage, "black")
				//set attributes here
				if !(SetNodeAttribute(g, hashValPackage, "nodeType", "Package") &&
					SetNodeAttribute(g, hashValPackage, "data", dependency.Package)) {
					return g, fmt.Errorf("error setting package node attribute(s)")
				}
			}

			//dependencyPackage node
			sort.Sort(packageNameSpaces(dependency.DependencyPackage.Namespaces))
			message = dependency.DependencyPackage.Type
			for _, namespace := range dependency.DependencyPackage.Namespaces {
				message += namespace.Namespace
				sort.Sort(packageNameSpacesNames(namespace.Names))
				for _, name := range namespace.Names {
					message += name.Name
					sort.Sort(packageNameSpacesNamesVersions(name.Versions))
					for _, version := range name.Versions {
						message += version.Version
						message += version.Subpath
						sort.Sort(packageNameSpacesNamesVersionsQualifiers(version.Qualifiers))
						for _, outlier := range version.Qualifiers {
							message += outlier.Key
							message += outlier.Value
						}
					}
				}
			}

			hashValDependencyPackage := nodeHasher([]byte(message))
			_, err = g.Vertex(hashValDependencyPackage)

			if err != nil { //node does not exist
				AddGraphNode(g, hashValDependencyPackage, "black")
				if !(SetNodeAttribute(g, hashValDependencyPackage, "nodeType", "DependencyPackage") &&
					SetNodeAttribute(g, hashValDependencyPackage, "data", dependency.DependencyPackage)) {
					return g, fmt.Errorf("error setting dependency package node attribute(s)")
				}
			}

			AddGraphEdge(g, hashValPackage, hashValDependencyPackage, "black")
		}
	}
	return g, nil
}
func nodeHasher(value []byte) string {
	hash := sha256.Sum256(value)
	return hex.EncodeToString(hash[:])
}

func AddGraphNode(g graph.Graph[string, *Node], _ID, color string) {
	var err error
	if _, err = g.Vertex(_ID); err == nil {
		return
	}

	newNode := &Node{
		ID:         _ID,
		Color:      color,
		Attributes: make(map[string]interface{}),
	}

	err = g.AddVertex(newNode, graph.VertexAttribute("color", color))
	if err != nil {
		return
	}
}

func AddGraphEdge(g graph.Graph[string, *Node], from, to, color string) {
	AddGraphNode(g, from, "black")
	AddGraphNode(g, to, "black")

	_, err := g.Edge(from, to)
	if err == nil {
		return
	}

	if g.AddEdge(from, to, graph.EdgeAttribute("color", color)) != nil {
		return
	}
}

func GraphEqual(graphOne, graphTwo graph.Graph[string, *Node]) (bool, error) {
	gOneMap, errOne := graphOne.AdjacencyMap()

	gTwoMap, errTwo := graphTwo.AdjacencyMap()

	if errOne != nil || errTwo != nil {
		return false, fmt.Errorf("error getting graph nodes")
	}

	if len(gTwoMap) != len(gOneMap) {
		return false, fmt.Errorf("number of nodes not equal")
	}

	for key := range gOneMap {
		_, ok := gTwoMap[key]
		if !ok {
			return false, fmt.Errorf("missing key in map")
		}
	}

	edgesOne, errOne := graphOne.Edges()
	edgesTwo, errTwo := graphTwo.Edges()
	if errOne != nil || errTwo != nil {
		return false, fmt.Errorf("error getting edges")
	}

	if len(edgesOne) != len(edgesTwo) {
		return false, fmt.Errorf("edges not equal")
	}

	for _, edge := range edgesOne {
		_, err := graphTwo.Edge(edge.Source, edge.Target)
		if err != nil {
			return false, fmt.Errorf("edge not found Source - %s Target - %s", edge.Source, edge.Target)
		}
	}
	return true, nil

}

func GraphEdgesEqual(graphOne, graphTwo graph.Graph[string, *Node]) (bool, error) {

	pathsOne, errOne := FindPathsFromHasSBOMNode(graphOne)
	pathsTwo, errTwo := FindPathsFromHasSBOMNode(graphTwo)
	if errOne != nil || errTwo != nil {
		return false, fmt.Errorf("error getting graph paths errOne-%v, errTwo-%v", errOne.Error(), errTwo.Error())
	}

	if len(pathsOne) != len(pathsTwo) {
		return false, fmt.Errorf("paths not of equal length %v %v", len(pathsOne), len(pathsTwo))
	}

	pathsOneStrings := concatenateLists(pathsOne)
	pathsTwoStrings := concatenateLists(pathsTwo)

	sort.Strings(pathsTwoStrings)
	sort.Strings(pathsOneStrings)

	for i := range pathsOneStrings {
		if pathsOneStrings[i] != pathsTwoStrings[i] {
			return false, fmt.Errorf("paths differ %v", fmt.Sprintf("%v", i))
		}
	}

	return true, nil
}

func concatenateLists(list [][]string) []string {
	var concatenated []string
	for _, l := range list {
		concatenated = append(concatenated, strings.Join(l, ""))
	}
	return concatenated
}

func nodeIDListToNodeList(g graph.Graph[string, *Node], list []string) ([]*Node, error) {

	var nodeList []*Node
	for _, item := range list {
		nd, err := g.Vertex(item)
		if err != nil {
			return nodeList, err
		}
		nodeList = append(nodeList, nd)
	}
	return nodeList, nil
}

func compareNodes(nodeOne, nodeTwo Node, nodeType string) ([]string, error) {
	var diffs []string
	var namespaceBig, namespaceSmall []model.AllPkgTreeNamespacesPackageNamespace

	var namesBig, namesSmall []model.AllPkgTreeNamespacesPackageNamespaceNamesPackageName
	var versionBig, versionSmall []model.AllPkgTreeNamespacesPackageNamespaceNamesPackageNameVersionsPackageVersion
	var qualifierBig, qualifierSmall []model.AllPkgTreeNamespacesPackageNamespaceNamesPackageNameVersionsPackageVersionQualifiersPackageQualifier
	dataOne, ok := nodeOne.Attributes["data"]

	if !ok {
		return []string{}, fmt.Errorf("could not get data attributes")
	}
	dataTwo, ok := nodeTwo.Attributes["data"]

	if !ok {
		return []string{}, fmt.Errorf("could not get data attributes")
	}

	switch nodeType {

	case "Package":

		nOne, ok := dataOne.(model.AllIsDependencyTreePackage)
		if !ok {
			return []string{}, fmt.Errorf("could not cast node to tree pkg")
		}

		nTwo, ok := dataTwo.(model.AllIsDependencyTreePackage)
		if !ok {
			return []string{}, fmt.Errorf("could not cast node to tree pkg")
		}

		if nodeOne.ID == nodeTwo.ID {
			return []string{}, nil
		}

		if nOne.Type != nTwo.Type {
			diffs = append(diffs, "Type: "+nOne.Type+" != "+nTwo.Type)

		}
		sort.Sort(packageNameSpaces(nOne.Namespaces))
		sort.Sort(packageNameSpaces(nTwo.Namespaces))

		if len(nTwo.Namespaces) > len(nOne.Namespaces) {
			namespaceBig = nTwo.Namespaces
			namespaceSmall = nOne.Namespaces
		} else if len(nTwo.Namespaces) < len(nOne.Namespaces) {
			namespaceBig = nOne.Namespaces
			namespaceSmall = nTwo.Namespaces
		} else {
			namespaceBig = nTwo.Namespaces
			namespaceSmall = nOne.Namespaces
		}

		// Compare namespaces
		for i, namespace1 := range namespaceBig {
			if i >= len(namespaceSmall) {
				diffs = append(diffs, fmt.Sprintf("Namespace %s not present", namespace1.Namespace))
				continue
			}
			namespace2 := namespaceSmall[i]

			sort.Sort(packageNameSpacesNames(namespace1.Names))
			sort.Sort(packageNameSpacesNames(namespace2.Names))

			// Compare namespace fields
			if namespace1.Namespace != namespace2.Namespace {
				diffs = append(diffs, fmt.Sprintf("Namespace %s != %s", namespace1.Namespace, namespace2.Namespace))
			}

			if len(namespace1.Names) > len(namespace2.Names) {
				namesBig = namespace1.Names
				namesSmall = namespace2.Names
			} else if len(namespace1.Names) < len(namespace2.Names) {
				namesBig = namespace2.Names
				namesSmall = namespace1.Names
			} else {
				namesBig = namespace1.Names
				namesSmall = namespace2.Names
			}

			// Compare names
			for j, name1 := range namesBig {

				if j >= len(namesSmall) {
					diffs = append(diffs, fmt.Sprintf("Name %s not present in namespace %s", name1.Name, namespace1.Namespace))
					continue
				}
				name2 := namesSmall[j]

				sort.Sort(packageNameSpacesNamesVersions(name1.Versions))
				sort.Sort(packageNameSpacesNamesVersions(name2.Versions))

				// Compare name fields
				if name1.Name != name2.Name {
					diffs = append(diffs, fmt.Sprintf("Name %s != %s in Namespace %s", name1.Name, name2.Name, namespace1.Namespace))

				}

				if len(name1.Versions) > len(name2.Versions) {
					versionBig = name1.Versions
					versionSmall = name2.Versions
				} else if len(name1.Versions) < len(name2.Versions) {
					versionBig = name2.Versions
					versionSmall = name1.Versions
				} else {
					versionBig = name1.Versions
					versionSmall = name2.Versions
				}

				// Compare versions
				for k, version1 := range versionBig {
					if k >= len(versionSmall) {
						diffs = append(diffs, fmt.Sprintf("Version %s not present for name %s in namespace %s,", version1.Version, name1.Name, namespace1.Namespace))
						continue

					}

					version2 := versionSmall[k]
					sort.Sort(packageNameSpacesNamesVersionsQualifiers(version1.Qualifiers))
					sort.Sort(packageNameSpacesNamesVersionsQualifiers(version2.Qualifiers))

					if version1.Version != version2.Version {
						diffs = append(diffs, fmt.Sprintf("Version %s != %s for name %s in namespace %s", version1.Version, version2.Version, name1.Name, namespace1.Namespace))
					}

					if version1.Subpath != version2.Subpath {
						diffs = append(diffs, fmt.Sprintf("Subpath %s != %s for version %s for name %s in namespace %s", version1.Subpath, version2.Subpath, version1.Version, name1.Name, namespace1.Namespace))
					}

					if len(version1.Qualifiers) > len(version2.Qualifiers) {
						qualifierBig = version1.Qualifiers
						qualifierSmall = version2.Qualifiers
					} else if len(version1.Qualifiers) < len(version2.Qualifiers) {
						qualifierBig = version2.Qualifiers
						qualifierSmall = version1.Qualifiers
					} else {
						qualifierBig = version1.Qualifiers
						qualifierSmall = version2.Qualifiers
					}

					for l, qualifier1 := range qualifierBig {
						if l >= len(qualifierSmall) {
							diffs = append(diffs, fmt.Sprintf("Qualifier %s:%s not present for version %s in name %s in namespace %s,", qualifier1.Key, qualifier1.Value, version1.Version, name1.Name, namespace1.Namespace))
							continue
						}

						qualifier2 := qualifierSmall[l]
						if qualifier2.Key != qualifier1.Key || qualifier1.Value != qualifier2.Value {

							diffs = append(diffs, fmt.Sprintf("Qualifier unequal for version %s in name %s in namespace %s:  %s:%s | %s:%s", version1.Version, name1.Name, namespace1.Namespace, qualifier1.Key, qualifier1.Value, qualifier2.Key, qualifier2.Value))

						}
					}
				}
			}
		}
	case "DependencyPackage":
		nOne, ok := dataOne.(model.AllIsDependencyTreeDependencyPackage)
		if !ok {
			return []string{}, fmt.Errorf("could not case node to tree dePkg")
		}

		nTwo, ok := dataTwo.(model.AllIsDependencyTreeDependencyPackage)
		if !ok {
			return []string{}, fmt.Errorf("could not case node to tree depPkg")
		}

		if nodeOne.ID == nodeTwo.ID {

			return []string{}, nil
		}

		if nOne.Type != nTwo.Type {
			diffs = append(diffs, "Type: "+nOne.Type+" != "+nTwo.Type)
		}
		sort.Sort(packageNameSpaces(nOne.Namespaces))
		sort.Sort(packageNameSpaces(nTwo.Namespaces))

		if len(nTwo.Namespaces) > len(nOne.Namespaces) {
			namespaceBig = nTwo.Namespaces
			namespaceSmall = nOne.Namespaces
		} else if len(nTwo.Namespaces) < len(nOne.Namespaces) {
			namespaceBig = nOne.Namespaces
			namespaceSmall = nTwo.Namespaces
		} else {
			namespaceBig = nTwo.Namespaces
			namespaceSmall = nOne.Namespaces
		}

		// Compare namespaces
		for i, namespace1 := range namespaceBig {
			if i >= len(namespaceSmall) {
				diffs = append(diffs, fmt.Sprintf("Namespace %s not present", namespace1.Namespace))
				continue
			}
			namespace2 := namespaceSmall[i]

			sort.Sort(packageNameSpacesNames(namespace1.Names))
			sort.Sort(packageNameSpacesNames(namespace2.Names))

			// Compare namespace fields
			if namespace1.Namespace != namespace2.Namespace {
				diffs = append(diffs, fmt.Sprintf("Namespace %s != %s", namespace1.Namespace, namespace2.Namespace))

			}

			if len(namespace1.Names) > len(namespace2.Names) {
				namesBig = namespace1.Names
				namesSmall = namespace2.Names
			} else if len(namespace1.Names) < len(namespace2.Names) {
				namesBig = namespace2.Names
				namesSmall = namespace1.Names
			} else {
				namesBig = namespace1.Names
				namesSmall = namespace2.Names
			}

			// Compare names
			for j, name1 := range namesBig {

				if j >= len(namesSmall) {
					diffs = append(diffs, fmt.Sprintf("Name %s not present in namespace %s", name1.Name, namespace1.Namespace))
					continue
				}
				name2 := namesSmall[j]

				sort.Sort(packageNameSpacesNamesVersions(name1.Versions))
				sort.Sort(packageNameSpacesNamesVersions(name2.Versions))

				// Compare name fields
				if name1.Name != name2.Name {
					diffs = append(diffs, fmt.Sprintf("Name %s != %s in Namespace %s", name1.Name, name2.Name, namespace1.Namespace))

				}

				if len(name1.Versions) > len(name2.Versions) {
					versionBig = name1.Versions
					versionSmall = name2.Versions
				} else if len(name1.Versions) < len(name2.Versions) {
					versionBig = name2.Versions
					versionSmall = name1.Versions
				} else {
					versionBig = name1.Versions
					versionSmall = name2.Versions
				}

				// Compare versions
				for k, version1 := range versionBig {
					if k >= len(versionSmall) {
						diffs = append(diffs, fmt.Sprintf("Version %s not present for name %s in namespace %s,", version1.Version, name1.Name, namespace1.Namespace))
						continue
					}

					version2 := versionSmall[k]
					sort.Sort(packageNameSpacesNamesVersionsQualifiers(version1.Qualifiers))
					sort.Sort(packageNameSpacesNamesVersionsQualifiers(version2.Qualifiers))

					if version1.Version != version2.Version {
						diffs = append(diffs, fmt.Sprintf("Version %s != %s for name %s in namespace %s", version1.Version, version2.Version, name1.Name, namespace1.Namespace))

					}

					if version1.Subpath != version2.Subpath {
						diffs = append(diffs, fmt.Sprintf("Subpath %s != %s for version %s for name %s in namespace %s,", version1.Subpath, version2.Subpath, version1.Version, name1.Name, namespace1.Namespace))

					}

					if len(version1.Qualifiers) > len(version2.Qualifiers) {
						qualifierBig = version1.Qualifiers
						qualifierSmall = version2.Qualifiers
					} else if len(version1.Qualifiers) < len(version2.Qualifiers) {
						qualifierBig = version2.Qualifiers
						qualifierSmall = version1.Qualifiers
					} else {
						qualifierBig = version1.Qualifiers
						qualifierSmall = version2.Qualifiers
					}

					for l, qualifier1 := range qualifierBig {
						if l >= len(qualifierSmall) {
							diffs = append(diffs, fmt.Sprintf("Qualifier %s:%s not present for version %s in name %s in namespace %s,", qualifier1.Key, qualifier1.Value, version1.Version, name1.Name, namespace1.Namespace))
							continue
						}
						qualifier2 := qualifierSmall[l]
						if qualifier2.Key != qualifier1.Key || qualifier1.Value != qualifier2.Value {

							diffs = append(diffs, fmt.Sprintf("Qualifier unequal for version %s in name %s in namespace %s:  %s:%s | %s:%s", version1.Version, name1.Name, namespace1.Namespace, qualifier1.Key, qualifier1.Value, qualifier2.Key, qualifier2.Value))
						}
					}
				}
			}
		}

	}
	return diffs, nil

}

func CompareTwoPaths(analysisListOne, analysisListTwo []*Node) ([][]string, int, error) {

	var longerPath, shorterPath []*Node
	var pathDiff [][]string
	var diffCount int

	if len(analysisListOne) > len(analysisListTwo) {
		longerPath = analysisListOne
		shorterPath = analysisListTwo
	} else if len(analysisListOne) < len(analysisListTwo) {
		longerPath = analysisListTwo
		shorterPath = analysisListOne
	} else {
		longerPath = analysisListOne
		shorterPath = analysisListTwo
	}

	for i, node := range longerPath {
		nodeType, ok := node.Attributes["nodeType"].(string)
		if !ok {
			return pathDiff, 0, fmt.Errorf("cannot case nodeType to string")
		}
		if i >= len(shorterPath) {
			dumnode := &Node{Attributes: make(map[string]interface{})}
			if nodeType == "Package" {
				dumnode.Attributes["data"] = model.AllIsDependencyTreePackage{}
			} else if nodeType == "DependencyPackage" {
				dumnode.Attributes["data"] = model.AllIsDependencyTreeDependencyPackage{}
			}

			diff, err := compareNodes(*node, *dumnode, nodeType)
			if err != nil {
				return pathDiff, 0, fmt.Errorf(err.Error())
			}

			pathDiff = append(pathDiff, diff)
			diffCount += len(diff)

		} else {
			diff, err := compareNodes(*node, *shorterPath[i], nodeType)
			if err != nil {
				return pathDiff, 0, fmt.Errorf(err.Error())
			}
			pathDiff = append(pathDiff, diff)
			diffCount += len(diff)
		}
	}

	return pathDiff, diffCount, nil

}

func CompareAllPaths(listOne, listTwo [][]*Node) ([]DiffedPath, error) {

	var small, big [][]*Node
	if len(listOne) > len(listTwo) {
		small= listTwo
		big = listOne
	} else if  len(listTwo) > len(listOne) {
		small= listOne
		big = listTwo
	} else {
		small= listTwo
		big = listOne
	}

	var results []DiffedPath
	used := make(map[int]bool)
	
	for _, pathOne := range  small {

		var diff DiffedPath
		diff.PathOne = pathOne
		min := math.MaxInt32
		var index int

		for i, pathTwo := range big {
			_, ok := used[i]
			if ok{
				continue
			}
			
			diffs, diffNum, err := CompareTwoPaths(pathOne, pathTwo)

			if err != nil {
				return results, fmt.Errorf(err.Error())
			}

			// if diffNum > //some number {
			// 	continue
			// }
			

			if diffNum < min {
				diff.PathTwo = pathTwo
				min = diffNum
				diff.Diffs = diffs
				index = i
			}
		}
		used[index] = true
		results = append(results, diff)
	}

	for i, val := range big {
		_, ok := used[i] 
		if !ok {
			results = append(results, DiffedPath{PathOne: val, })
		}
	}


	return results, nil
}

func GetNodeString(option int, node interface{}) (string, error) {
	switch option {

	case 1:
		pkg, ok := node.(model.AllIsDependencyTreePackage)
		if !ok {
			return "", fmt.Errorf("could not case node to tree Pkg")
		}

		sort.Sort(packageNameSpaces(pkg.Namespaces))
		message := "Type:" + pkg.Type + "\n"
		for _, namespace := range pkg.Namespaces {
			message += "Namespace: " + namespace.Namespace + "\n"

			for _, name := range namespace.Names {
				message += "\t"
				message += "Name: " + name.Name
				message += "\n"

				for _, version := range name.Versions {
					message += "\t\t"
					message += "Version: " + version.Version + "\n"
					message += "\t\t"
					message += "Subpath: " + version.Subpath + "\n"
					message += "\t\tQualifiers: {\n"

					for _, outlier := range version.Qualifiers {
						message += "\t\t\t"
						message += outlier.Key + ": " + outlier.Value + "\n"
					}
					message += "\t\t}\n"
				}
			}
			message += "\n"
		}
		return message, nil
	case 2:
		depPkg, ok := node.(model.AllIsDependencyTreeDependencyPackage)
		if !ok {
			return "", fmt.Errorf("could not case node to tree depPkg")
		}

		message := "Type:" + CheckEmpty(depPkg.Type) + "\n"
		for _, namespace := range depPkg.Namespaces {
			message += "Namespace: " + CheckEmpty(namespace.Namespace) + "\n"

			for _, name := range namespace.Names {
				message += "\t"
				message += "Name: " + CheckEmpty(name.Name)
				message += "\n"

				for _, version := range name.Versions {
					message += "\t\t"
					message += "Version: " + CheckEmpty(version.Version) + "\n"
					message += "\t\t"
					message += "Subpath: " + CheckEmpty(version.Subpath) + "\n"
					message += "\t\tQualifiers: {\n"

					for _, outlier := range version.Qualifiers {
						message += "\t\t\t"
						message += CheckEmpty(outlier.Key) + ": " + CheckEmpty(outlier.Value) + "\n"
					}
					message += "\t\t}\n"
				}
			}
			message += "\n"
		}
		return message, nil

	}

	return "", nil
}

func CheckEmpty(value string) string {
	if len(value) > 20 {
		return value[:20] + "..."
	}
	if value == "" {
		return "\"\""
	}
	return value
}