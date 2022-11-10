package utils

import (
	"bufio"
	"encoding/json"
	"io/ioutil"
	"os"
	"path/filepath"
)

func ReadLines(filename string) (lines []string, err error) {
	f, err := os.Open(filename)
	if err != nil {
		return
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	for s.Scan() {
		lines = append(lines, s.Text())
	}
	return
}

func FileExists(filename string) bool {
	info, err := os.Stat(filename)
	if os.IsNotExist(err) || err != nil || info == nil {
		return false
	}
	return !info.IsDir()
}

func ReadFile(filename string) (bytes []byte, err error) {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return
	}
	return data, nil
}

func WriteFile(filename string, data string) (err error) {
	file, err := os.OpenFile(filename, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0666)
	if err != nil {
		return err
	}
	writer := bufio.NewWriter(file)
	_, _ = writer.WriteString(data)
	_ = writer.Flush()
	return nil
}

func SaveMarshal(filename string, results interface{}) (err error) {
	var data []byte
	data, err = json.Marshal(results)
	if err != nil {
		return
	}
	err = WriteFile(filename, string(data))
	return
}

func GetAllFile(dirPath string) (results []string, err error) {
	err = filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
		if !info.IsDir() {
			results = append(results, path)
		}
		return nil
	})
	if err != nil {
		return
	}
	return
}
