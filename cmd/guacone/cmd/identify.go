//
// Copyright 2022 The GUAC Authors.
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

package cmd

import (



	"github.com/spf13/cobra"
	"github.com/guacsec/guac/pkg/identifier"
)



var identifyCmd = &cobra.Command{
	Use:   "identify",
	Short: "identify",
	Run: func(cmd *cobra.Command, args []string) {

		sboms, _ := identifier.ProcessSBOMFilesInDirectory("/Users/arorasoham9/Desktop/soham_work/guac_alll/guac-data/docs/cyclonedx")
		idsboms, _:= identifier.ProcessIDsFromSBOMs(sboms)
		identifier.FindArtifactConflicts(idsboms)
		


		
	},
}


func init() {
	rootCmd.AddCommand(identifyCmd)
}
