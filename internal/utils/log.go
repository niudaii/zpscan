package utils

import (
	"fmt"
	"os"
	"sync"

	"github.com/projectdiscovery/gologger/levels"
	"github.com/projectdiscovery/gologger/writer"
)

type CLI struct {
	outputFile string
	mutex      *sync.Mutex
}

var _ writer.Writer = &CLI{}

func NewCLI(outputFile string) *CLI {
	cli := &CLI{
		outputFile: outputFile,
		mutex:      &sync.Mutex{},
	}
	if !FileExists(outputFile) {
		fp, err := os.Create(outputFile)
		if err != nil {
			fmt.Printf("Create %v err, %v\n", outputFile, err)
			return cli
		}
		defer fp.Close()
	}
	return cli
}

func (w *CLI) Write(data []byte, level levels.Level) {
	w.mutex.Lock()
	defer w.mutex.Unlock()

	switch level {
	case levels.LevelSilent:
		os.Stdout.Write(data)
		os.Stdout.Write([]byte("\n"))

	default:
		os.Stderr.Write(data)
		os.Stderr.Write([]byte("\n"))
	}
	fl, err := os.OpenFile(w.outputFile, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		fmt.Printf("Open %v err, %v\n", w.outputFile, err)
		return
	}
	_, _ = fl.Write(data)
	_, _ = fl.Write([]byte("\n"))
	fl.Close()
}
