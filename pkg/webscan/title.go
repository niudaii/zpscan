package webscan

import (
	"bytes"
	"fmt"
	"io"
	"regexp"
	"strings"

	"github.com/imroc/req/v3"
	"golang.org/x/net/html"
)

var (
	cutset  = "\n\t\v\f\r"
	reTitle = regexp.MustCompile(`(?im)<\s*title.*>(.*?)<\s*/\s*title>`)
)

func GetTitle(resp *req.Response) (title string) {
	// Try to parse the DOM
	titleDom, err := getTitleWithDom(resp)
	// In case of error fallback to regex
	if err != nil {
		for _, match := range reTitle.FindAllString(resp.String(), -1) {
			title = match
			break
		}
	} else {
		title = renderNode(titleDom)
	}
	title = html.UnescapeString(trimTitleTags(title))
	// remove unwanted chars
	title = strings.TrimSpace(strings.Trim(title, cutset))
	title = strings.ReplaceAll(title, "\n", "")
	title = strings.ReplaceAll(title, "\r", "")
	return //nolint
}

func getTitleWithDom(r *req.Response) (*html.Node, error) {
	var title *html.Node
	var crawler func(*html.Node)
	crawler = func(node *html.Node) {
		if node.Type == html.ElementNode && node.Data == "title" {
			title = node
			return
		}
		for child := node.FirstChild; child != nil; child = child.NextSibling {
			crawler(child)
		}
	}
	htmlDoc, err := html.Parse(bytes.NewReader(r.Bytes()))
	if err != nil {
		return nil, err
	}
	crawler(htmlDoc)
	if title != nil {
		return title, nil
	}
	return nil, fmt.Errorf("Title not found")
}

func renderNode(n *html.Node) string {
	var buf bytes.Buffer
	w := io.Writer(&buf)
	html.Render(w, n) //nolint
	return buf.String()
}

func trimTitleTags(title string) string {
	// trim <title>*</title>
	titleBegin := strings.Index(title, ">")
	titleEnd := strings.Index(title, "</")
	if titleEnd < 0 || titleBegin < 0 {
		return title
	}
	return title[titleBegin+1 : titleEnd]
}
