package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/htun-project/htun/internal/gateway"
)

func loadClientTokens(path string) (map[string]string, error) {
	tokens := make(map[string]string)
	if strings.TrimSpace(path) == "" {
		return tokens, nil
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open client token file: %w", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for lineNumber := 1; scanner.Scan(); lineNumber++ {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		clientID, token, ok := strings.Cut(line, "=")
		clientID = strings.TrimSpace(clientID)
		token = strings.TrimSpace(token)
		if !ok || !gateway.ValidClientID(clientID) {
			return nil, fmt.Errorf("client token file line %d has an invalid client ID assignment", lineNumber)
		}
		if len(token) < 16 {
			return nil, fmt.Errorf("client token file line %d has a token shorter than 16 characters", lineNumber)
		}
		if _, exists := tokens[clientID]; exists {
			return nil, fmt.Errorf("client token file line %d duplicates client ID %q", lineNumber, clientID)
		}
		tokens[clientID] = token
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read client token file: %w", err)
	}
	return tokens, nil
}
