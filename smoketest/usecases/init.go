package usecases

import "fmt"

type Runner func(string, string) Response

type Test struct {
	Title string
	Run   Runner
}

type Response struct {
	Success     bool
	Description string
}

type Tests struct {
	Title    string
	UseCases []Test
}

func (ouc Tests) Run(proto, address string) []Response {
	result := make([]Response, len(ouc.UseCases))
	fmt.Printf("Testing %s\n", ouc.Title)
	for i, t := range ouc.UseCases {
		fmt.Printf("\t%s\t", t.Title)
		result[i] = t.Run(proto, address)
		if !result[i].Success {
			fmt.Printf("\x1B[31mX\x1B[0m\n")
		} else {
			fmt.Printf("\x1B[32m✓\x1B[0m\n")
		}
	}
	return result
}
