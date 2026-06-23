package engine

import "go.woodpecker-ci.org/woodpecker/v3/woodpecker-go/woodpecker"

func countTasksByLabels(jobs []woodpecker.Task, requiredLabels map[string]string) int {
	count := 0
	for _, job := range jobs {
		isMatch := true
		for labelKey, labelValue := range requiredLabels {
			val, exists := job.Labels[labelKey]
			if !exists || val != labelValue {
				isMatch = false
				break
			}
		}

		if isMatch {
			count++
		}
	}
	return count
}
