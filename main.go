package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/json"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

var DefaultHostKeys = []string{
	"server",
	"host",
	"hostname",
	"sni",
	"servername",
	"server_name",
	"peer",
	"endpoint",
	"domain",
	"address",
}

var DefaultSecretKeys = []string{
	"password",
	"passwd",
	"pass",
	"uuid",
	"private-key",
	"private_key",
	"psk",
	"auth",
	"auth-str",
	"auth_str",
	"obfs-password",
	"obfs_password",
	"token",
	"secret",
}

const (
	MapVersion = 2
	MapTool    = "clashmask"
)

var proxyRootStartRe = regexp.MustCompile(`(?i)^\s*(?:[{,]\s*)?["']?(proxy|proxies)["']?\s*:\s*(.*)$`)
var singboxRootStartRe = regexp.MustCompile(`(?i)^\s*(?:[{,]\s*)?["']?(outbounds|inbounds|endpoints)["']?\s*:\s*(.*)$`)

const (
	maskModeClash   = "clash"
	maskModeSingbox = "singbox"
)

type Config struct {
	HostKeys   []string
	SecretKeys []string
}

type TokenMap struct {
	Version      int               `json:"version"`
	Tool         string            `json:"tool"`
	CreatedAt    string            `json:"created_at"`
	MaskedSHA256 string            `json:"masked_sha256"`
	Host         map[string]string `json:"host"`
	Secret       map[string]string `json:"secret"`
}

type Sanitizer struct {
	hostKVRe    *regexp.Regexp
	secretKVRe  *regexp.Regexp
	uriHostRe   *regexp.Regexp
	uriSecretRe *regexp.Regexp

	hostOriginalToToken   map[string]string
	secretOriginalToToken map[string]string
	hostTokenToOriginal   map[string]string
	secretTokenToOriginal map[string]string

	hostCounter   int
	secretCounter int
}

func main() {
	reader := bufio.NewReader(os.Stdin)
	if err := runInteractive(reader); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func runInteractive(reader *bufio.Reader) error {
	fmt.Println("clashmask (interactive)")
	fmt.Println("1) Mask config")
	fmt.Println("2) Unmask config")
	mode, err := promptRequired(reader, "Choose mode (1/2)", "")
	if err != nil {
		return err
	}
	switch strings.TrimSpace(mode) {
	case "1", "mask", "Mask", "MASK":
		return runMaskInteractive(reader)
	case "2", "unmask", "Unmask", "UNMASK":
		return runUnmaskInteractive(reader)
	default:
		return errors.New("invalid mode, please choose 1 or 2")
	}
}

func runMaskInteractive(reader *bufio.Reader) error {
	inputPath, err := selectMaskInputPathInteractive(reader)
	if err != nil {
		return err
	}
	inputPath = strings.TrimSpace(inputPath)

	data, err := os.ReadFile(inputPath)
	if err != nil {
		return err
	}

	inPlace, err := promptYesNo(reader, "Overwrite input file in place", false)
	if err != nil {
		return err
	}

	defaultOut := addSuffixBeforeExt(inputPath, ".masked")
	outPath := defaultOut
	if inPlace {
		outPath = inputPath
	} else {
		outPath, err = promptRequired(reader, "Masked output path", defaultOut)
		if err != nil {
			return err
		}
	}

	mapPath, err := buildGeneratedMapPath(outPath)
	if err != nil {
		return err
	}

	customKeys, err := promptYesNo(reader, "Customize host/secret key lists", false)
	if err != nil {
		return err
	}

	hostKeys := DefaultHostKeys
	secretKeys := DefaultSecretKeys
	if customKeys {
		hostRaw, err := promptRequired(reader, "Host keys (comma-separated)", strings.Join(DefaultHostKeys, ","))
		if err != nil {
			return err
		}
		secretRaw, err := promptRequired(reader, "Secret keys (comma-separated)", strings.Join(DefaultSecretKeys, ","))
		if err != nil {
			return err
		}
		hostKeys = parseCSV(hostRaw)
		secretKeys = parseCSV(secretRaw)
	}

	sanitizer, err := NewSanitizer(Config{HostKeys: hostKeys, SecretKeys: secretKeys})
	if err != nil {
		return err
	}

	masked := sanitizer.MaskText(string(data))
	if err := os.WriteFile(outPath, []byte(masked), 0o644); err != nil {
		return err
	}
	if err := SaveTokenMap(mapPath, sanitizer.ExportMap(masked)); err != nil {
		return err
	}

	fmt.Println("")
	fmt.Println("Mask complete")
	fmt.Println("masked file:", outPath)
	fmt.Println("map file (auto-generated):", mapPath)
	fmt.Println("To restore, run this program again and choose 2 (Unmask).")
	return nil
}

func selectMaskInputPathInteractive(reader *bufio.Reader) (string, error) {
	files, err := discoverMaskCandidateFilesInDir(".")
	if err != nil {
		return "", err
	}
	if len(files) == 0 {
		return promptRequired(reader, "No candidate config files found, enter input file path", "")
	}

	fmt.Println("Config files in current folder (.yaml/.yml/.json/.jsonc):")
	for i, f := range files {
		fmt.Printf("%d) %s\n", i+1, f)
	}
	fmt.Println("0) Enter path manually")

	for {
		raw, err := promptRequired(reader, "Choose file number", "1")
		if err != nil {
			return "", err
		}
		n, convErr := strconv.Atoi(strings.TrimSpace(raw))
		if convErr != nil {
			fmt.Println("please input a valid number")
			continue
		}
		if n == 0 {
			return promptRequired(reader, "Input clash file path", "")
		}
		if n >= 1 && n <= len(files) {
			return files[n-1], nil
		}
		fmt.Println("number out of range")
	}
}

func runUnmaskInteractive(reader *bufio.Reader) error {
	inputPath, err := promptRequired(reader, "Input masked file path", "")
	if err != nil {
		return err
	}
	inputPath = strings.TrimSpace(inputPath)

	data, err := os.ReadFile(inputPath)
	if err != nil {
		return err
	}

	mapPath, err := selectMapPathInteractive(reader, inputPath, data)
	if err != nil {
		return err
	}
	mapping, err := LoadTokenMap(mapPath)
	if err != nil {
		return err
	}
	warnings, err := CheckMapForUnmask(mapping, data)
	if err != nil {
		return err
	}
	for _, w := range warnings {
		fmt.Println("warning:", w)
	}

	inPlace, err := promptYesNo(reader, "Overwrite masked file in place", false)
	if err != nil {
		return err
	}

	defaultOut := addSuffixBeforeExt(inputPath, ".restored")
	outPath := defaultOut
	if inPlace {
		outPath = inputPath
	} else {
		outPath, err = promptRequired(reader, "Restored output path", defaultOut)
		if err != nil {
			return err
		}
	}

	restored, replaced := UnmaskTextWithCount(string(data), mapping)
	if err := os.WriteFile(outPath, []byte(restored), 0o644); err != nil {
		return err
	}

	fmt.Println("")
	fmt.Println("Unmask complete")
	fmt.Println("replaced tokens:", replaced)
	if replaced == 0 {
		fmt.Println("warning: no masked tokens found in input content")
	}
	fmt.Println("restored file:", outPath)
	return nil
}

func promptRequired(reader *bufio.Reader, label string, def string) (string, error) {
	for {
		v, err := prompt(reader, label, def)
		if err != nil {
			return "", err
		}
		if strings.TrimSpace(v) != "" {
			return v, nil
		}
		fmt.Println("value cannot be empty")
	}
}

func prompt(reader *bufio.Reader, label string, def string) (string, error) {
	if def == "" {
		fmt.Printf("%s: ", label)
	} else {
		fmt.Printf("%s [%s]: ", label, def)
	}
	raw, err := reader.ReadString('\n')
	if err != nil {
		if errors.Is(err, os.ErrClosed) {
			return "", err
		}
		if errors.Is(err, io.EOF) {
			raw = strings.TrimSpace(raw)
			if raw == "" {
				return "", io.EOF
			}
			return raw, nil
		}
		if raw == "" {
			return "", err
		}
	}
	value := strings.TrimSpace(raw)
	if value == "" {
		return def, nil
	}
	return value, nil
}

func promptYesNo(reader *bufio.Reader, label string, def bool) (bool, error) {
	defText := "n"
	if def {
		defText = "y"
	}
	for {
		v, err := prompt(reader, label+" (y/n)", defText)
		if err != nil {
			return false, err
		}
		switch strings.ToLower(strings.TrimSpace(v)) {
		case "y", "yes":
			return true, nil
		case "n", "no":
			return false, nil
		default:
			fmt.Println("please input y or n")
		}
	}
}

func addSuffixBeforeExt(path string, suffix string) string {
	ext := filepath.Ext(path)
	if ext == "" {
		return path + suffix
	}
	base := strings.TrimSuffix(path, ext)
	return base + suffix + ext
}

func buildGeneratedMapPath(targetPath string) (string, error) {
	ext := filepath.Ext(targetPath)
	base := strings.TrimSuffix(targetPath, ext)
	if base == "" {
		base = targetPath
	}
	candidate := base + ".maskmap.json"
	if !fileExists(candidate) {
		return candidate, nil
	}
	stamp := time.Now().Format("20060102_150405")
	candidate = base + "." + stamp + ".maskmap.json"
	if !fileExists(candidate) {
		return candidate, nil
	}
	for i := 1; i <= 999; i++ {
		next := base + "." + stamp + "_" + strconv.Itoa(i) + ".maskmap.json"
		if !fileExists(next) {
			return next, nil
		}
	}
	return "", errors.New("unable to create unique map path")
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func selectMapPathInteractive(reader *bufio.Reader, maskedInputPath string, inputData []byte) (string, error) {
	files, err := discoverMapFilesInCWD()
	if err != nil {
		return "", err
	}
	if len(files) == 0 {
		return promptRequired(reader, "No map file found in current directory, enter map file path", "")
	}

	fmt.Println("Map files in current directory:")
	for i, f := range files {
		fmt.Printf("%d) %s\n", i+1, f)
	}
	fmt.Println("0) Enter path manually")

	defaultChoice := "1"
	expected := defaultMapFilenameForMaskedInput(maskedInputPath)
	if expected != "" {
		for i, f := range files {
			if f == expected {
				defaultChoice = strconv.Itoa(i + 1)
				goto promptSelectMap
			}
		}
	}
	if bestIdx, bestScore := findBestMapByTokenOverlap(files, string(inputData)); bestIdx >= 0 && bestScore > 0 {
		defaultChoice = strconv.Itoa(bestIdx + 1)
	}

promptSelectMap:
	for {
		raw, err := promptRequired(reader, "Choose map file number", defaultChoice)
		if err != nil {
			return "", err
		}
		n, convErr := strconv.Atoi(strings.TrimSpace(raw))
		if convErr != nil {
			fmt.Println("please input a valid number")
			continue
		}
		if n == 0 {
			return promptRequired(reader, "Map file path", "")
		}
		if n >= 1 && n <= len(files) {
			return files[n-1], nil
		}
		fmt.Println("number out of range")
	}
}

func findBestMapByTokenOverlap(mapFiles []string, inputContent string) (int, int) {
	bestIdx := -1
	bestScore := 0
	if strings.TrimSpace(inputContent) == "" {
		return bestIdx, bestScore
	}
	for i, p := range mapFiles {
		m, err := LoadTokenMap(p)
		if err != nil {
			continue
		}
		score := 0
		for token := range m.Host {
			if strings.Contains(inputContent, token) {
				score++
			}
		}
		for token := range m.Secret {
			if strings.Contains(inputContent, token) {
				score++
			}
		}
		if score > bestScore {
			bestScore = score
			bestIdx = i
		}
	}
	return bestIdx, bestScore
}

func defaultMapFilenameForMaskedInput(maskedInputPath string) string {
	base := filepath.Base(maskedInputPath)
	ext := filepath.Ext(base)
	if ext == "" {
		return base + ".maskmap.json"
	}
	return strings.TrimSuffix(base, ext) + ".maskmap.json"
}

func discoverMapFilesInCWD() ([]string, error) {
	entries, err := os.ReadDir(".")
	if err != nil {
		return nil, err
	}
	files := make([]string, 0, len(entries))
	for _, ent := range entries {
		if ent.IsDir() {
			continue
		}
		name := ent.Name()
		if strings.HasSuffix(name, ".maskmap.json") {
			files = append(files, name)
		}
	}
	sort.Strings(files)
	return files, nil
}

func discoverMaskCandidateFilesInDir(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	files := make([]string, 0, len(entries))
	for _, ent := range entries {
		if ent.IsDir() {
			continue
		}
		name := ent.Name()
		lower := strings.ToLower(name)
		if strings.HasSuffix(lower, ".yaml") || strings.HasSuffix(lower, ".yml") || strings.HasSuffix(lower, ".json") || strings.HasSuffix(lower, ".jsonc") {
			files = append(files, name)
		}
	}
	sort.Strings(files)
	return files, nil
}

func NewSanitizer(cfg Config) (*Sanitizer, error) {
	hostKeys := cfg.HostKeys
	if len(hostKeys) == 0 {
		hostKeys = DefaultHostKeys
	}
	secretKeys := cfg.SecretKeys
	if len(secretKeys) == 0 {
		secretKeys = DefaultSecretKeys
	}
	hostPattern := buildKVPattern(hostKeys)
	secretPattern := buildKVPattern(secretKeys)
	if hostPattern == "" || secretPattern == "" {
		return nil, errors.New("host-keys and secret-keys must not be empty")
	}
	return &Sanitizer{
		hostKVRe:              regexp.MustCompile(hostPattern),
		secretKVRe:            regexp.MustCompile(secretPattern),
		uriSecretRe:           regexp.MustCompile(`(?i)\b((?:ss|trojan|tuic|hysteria2?|vless|vmess)://)([^/@\s#]+)(@)`),
		uriHostRe:             regexp.MustCompile(`(?i)\b([a-z][a-z0-9+.-]*://(?:[^/@\s#]+@)?)(\[[^\]]+\]|[^:/\s?#,\]}"]+)(:\d+)?`),
		hostOriginalToToken:   make(map[string]string),
		secretOriginalToToken: make(map[string]string),
		hostTokenToOriginal:   make(map[string]string),
		secretTokenToOriginal: make(map[string]string),
	}, nil
}

func buildKVPattern(keys []string) string {
	var escaped []string
	for _, k := range keys {
		k = strings.TrimSpace(k)
		if k == "" {
			continue
		}
		escaped = append(escaped, regexp.QuoteMeta(k))
	}
	if len(escaped) == 0 {
		return ""
	}
	return `(?i)(["']?(?:` + strings.Join(escaped, "|") + `)["']?\s*[:=]\s*)(\"([^\"]*)\"|'([^']*)'|([^,\s#}\]]+))`
}

func (s *Sanitizer) hostToken(raw string) string {
	if token, ok := s.hostOriginalToToken[raw]; ok {
		return token
	}
	s.hostCounter++
	token := "__CLASHMASK_HOST_" + leftPadInt(s.hostCounter, 5) + "__"
	s.hostOriginalToToken[raw] = token
	s.hostTokenToOriginal[token] = raw
	return token
}

func (s *Sanitizer) secretToken(raw string) string {
	if token, ok := s.secretOriginalToToken[raw]; ok {
		return token
	}
	s.secretCounter++
	token := "__CLASHMASK_SECRET_" + leftPadInt(s.secretCounter, 5) + "__"
	s.secretOriginalToToken[raw] = token
	s.secretTokenToOriginal[token] = raw
	return token
}

func leftPadInt(n int, width int) string {
	raw := strconv.Itoa(n)
	if len(raw) >= width {
		return raw
	}
	return strings.Repeat("0", width-len(raw)) + raw
}

func (s *Sanitizer) MaskText(input string) string {
	mode := detectMaskMode(input)
	if mode == maskModeSingbox {
		return s.maskSingboxText(input)
	}
	return s.maskClashText(input)
}

func detectMaskMode(input string) string {
	hasClash := hasRootKeyByLine(input, []string{"proxy", "proxies"})
	hasSingbox := hasRootKeyByLine(input, []string{"outbounds", "inbounds", "endpoints"})

	if hasClash && !hasSingbox {
		return maskModeClash
	}
	if hasSingbox && !hasClash {
		return maskModeSingbox
	}
	if hasSingbox && hasClash {
		trim := strings.TrimSpace(input)
		if strings.HasPrefix(trim, "{") || strings.HasPrefix(trim, "[") {
			return maskModeSingbox
		}
		return maskModeClash
	}
	trim := strings.TrimSpace(input)
	if strings.HasPrefix(trim, "{") || strings.HasPrefix(trim, "[") {
		return maskModeSingbox
	}
	return maskModeClash
}

func hasRootKeyByLine(input string, keys []string) bool {
	start := 0
	for start < len(input) {
		rel := strings.IndexByte(input[start:], '\n')
		line := ""
		if rel == -1 {
			line = input[start:]
			start = len(input)
		} else {
			pos := start + rel
			line = input[start:pos]
			start = pos + 1
		}
		code, _ := splitCodeAndComment(line)
		trimmed := strings.TrimSpace(code)
		if trimmed == "" {
			continue
		}
		for _, key := range keys {
			if isLikelyRootKeyLine(code, key) {
				return true
			}
		}
	}
	return false
}

func isLikelyRootKeyLine(code string, key string) bool {
	trim := strings.TrimSpace(code)
	keyLower := strings.ToLower(key)
	candidates := []string{
		keyLower + ":",
		"\"" + keyLower + "\":",
		"'" + keyLower + "':",
	}
	for _, c := range candidates {
		if strings.HasPrefix(strings.ToLower(trim), c) {
			return true
		}
		if strings.HasPrefix(strings.ToLower(trim), "{"+c) || strings.HasPrefix(strings.ToLower(trim), ","+c) {
			return true
		}
	}
	return false
}

func (s *Sanitizer) maskClashText(input string) string {
	if input == "" {
		return ""
	}

	var out strings.Builder
	start := 0
	inProxies := false
	proxiesIndent := 0
	jsonArrayMode := false
	jsonArrayDepth := 0

	for start < len(input) {
		rel := strings.IndexByte(input[start:], '\n')
		line := ""
		newline := ""
		if rel == -1 {
			line = input[start:]
			start = len(input)
		} else {
			pos := start + rel
			line = input[start:pos]
			newline = "\n"
			start = pos + 1
		}

		lineIndent := leadingIndentWidth(line)
		code, comment := splitCodeAndComment(line)
		trimmed := strings.TrimSpace(code)
		indent := leadingIndentWidth(code)
		maskThisLine := false
		startedProxiesNow := false

		if inProxies {
			if jsonArrayMode {
				maskThisLine = true
			} else {
				if trimmed == "" {
					// If the line is a root-level comment, treat it as outside the proxy block.
					if comment != "" && lineIndent <= proxiesIndent {
						inProxies = false
						jsonArrayMode = false
						jsonArrayDepth = 0
					} else {
						maskThisLine = true
					}
				} else if indent > proxiesIndent {
					maskThisLine = true
				} else {
					inProxies = false
					jsonArrayMode = false
					jsonArrayDepth = 0
				}
			}
		}

		if !inProxies {
			if ok, afterColon := parseProxyRootStart(code, indent); ok {
				inProxies = true
				startedProxiesNow = true
				maskThisLine = true
				proxiesIndent = indent
				jsonArrayMode = false
				jsonArrayDepth = 0

				if strings.Contains(afterColon, "[") {
					jsonArrayMode = true
					jsonArrayDepth = bracketDeltaIgnoringQuotes(afterColon)
					if jsonArrayDepth <= 0 {
						inProxies = false
						jsonArrayMode = false
						jsonArrayDepth = 0
					}
				}
			}
		}

		if maskThisLine {
			code = s.maskCodeSegment(code)
		}
		if maskThisLine && comment != "" {
			comment = s.maskCommentSegment(comment)
		}

		if inProxies && jsonArrayMode && !startedProxiesNow {
			jsonArrayDepth += bracketDeltaIgnoringQuotes(code)
			if jsonArrayDepth <= 0 {
				inProxies = false
				jsonArrayMode = false
				jsonArrayDepth = 0
			}
		}

		out.WriteString(code)
		out.WriteString(comment)
		out.WriteString(newline)
	}

	return out.String()
}

func (s *Sanitizer) maskSingboxText(input string) string {
	if input == "" {
		return ""
	}

	var out strings.Builder
	start := 0
	globalBraceDepth := 0
	inSection := false
	sectionDepth := 0
	startedSectionNow := false

	for start < len(input) {
		rel := strings.IndexByte(input[start:], '\n')
		line := ""
		newline := ""
		if rel == -1 {
			line = input[start:]
			start = len(input)
		} else {
			pos := start + rel
			line = input[start:pos]
			newline = "\n"
			start = pos + 1
		}

		code, comment := splitCodeAndComment(line)
		maskThisLine := false
		startedSectionNow = false

		if inSection {
			maskThisLine = true
		}

		if !inSection {
			if ok, afterColon := parseSingboxRootStart(code, globalBraceDepth); ok {
				inSection = true
				startedSectionNow = true
				maskThisLine = true
				sectionDepth = containerDeltaIgnoringQuotes(afterColon)
				if sectionDepth <= 0 {
					inSection = false
					sectionDepth = 0
				}
			}
		}

		if maskThisLine {
			code = s.maskCodeSegment(code)
			if comment != "" {
				comment = s.maskCommentSegment(comment)
			}
		}

		if inSection && !startedSectionNow {
			sectionDepth += containerDeltaIgnoringQuotes(code)
			if sectionDepth <= 0 {
				inSection = false
				sectionDepth = 0
			}
		}

		globalBraceDepth += braceDeltaIgnoringQuotes(code)
		if globalBraceDepth < 0 {
			globalBraceDepth = 0
		}

		out.WriteString(code)
		out.WriteString(comment)
		out.WriteString(newline)
	}
	return out.String()
}

func (s *Sanitizer) maskCodeSegment(code string) string {
	masked := code
	masked = s.replaceKV(masked, s.secretKVRe, s.secretToken)
	masked = s.replaceKV(masked, s.hostKVRe, s.hostToken)
	masked = s.replaceURICredentials(masked)
	masked = s.replaceURIHosts(masked)
	return masked
}

func (s *Sanitizer) maskCommentSegment(comment string) string {
	if strings.TrimSpace(comment) == "" {
		return comment
	}
	return s.maskCodeSegment(comment)
}

func (s *Sanitizer) replaceKV(input string, re *regexp.Regexp, tokenFn func(string) string) string {
	return re.ReplaceAllStringFunc(input, func(match string) string {
		sub := re.FindStringSubmatch(match)
		if len(sub) < 6 {
			return match
		}
		prefix := sub[1]
		fullValue := sub[2]
		rawValue := sub[5]
		quote := ""
		if sub[3] != "" {
			rawValue = sub[3]
			quote = `"`
		} else if sub[4] != "" {
			rawValue = sub[4]
			quote = `'`
		} else if strings.HasPrefix(fullValue, `"`) && strings.HasSuffix(fullValue, `"`) {
			quote = `"`
		} else if strings.HasPrefix(fullValue, `'`) && strings.HasSuffix(fullValue, `'`) {
			quote = `'`
		}
		if strings.TrimSpace(rawValue) == "" {
			return match
		}
		token := tokenFn(rawValue)
		if quote != "" {
			return prefix + quote + token + quote
		}
		return prefix + token
	})
}

func (s *Sanitizer) replaceURICredentials(input string) string {
	return s.uriSecretRe.ReplaceAllStringFunc(input, func(match string) string {
		sub := s.uriSecretRe.FindStringSubmatch(match)
		if len(sub) < 4 {
			return match
		}
		schemePrefix := sub[1]
		userinfo := sub[2]
		at := sub[3]
		lower := strings.ToLower(strings.TrimSuffix(schemePrefix, "://"))
		newUser := userinfo
		if lower == "ss" && strings.Contains(userinfo, ":") {
			parts := strings.SplitN(userinfo, ":", 2)
			if len(parts) == 2 {
				newUser = parts[0] + ":" + s.secretToken(parts[1])
			}
		} else {
			newUser = s.secretToken(userinfo)
		}
		return schemePrefix + newUser + at
	})
}

func (s *Sanitizer) replaceURIHosts(input string) string {
	return s.uriHostRe.ReplaceAllStringFunc(input, func(match string) string {
		sub := s.uriHostRe.FindStringSubmatch(match)
		if len(sub) < 3 {
			return match
		}
		prefix := sub[1]
		host := sub[2]
		port := ""
		if len(sub) >= 4 {
			port = sub[3]
		}
		hostRaw := strings.Trim(host, "[]")
		if strings.TrimSpace(hostRaw) == "" {
			return match
		}
		token := s.hostToken(hostRaw)
		return prefix + token + port
	})
}

func (s *Sanitizer) ExportMap(masked string) TokenMap {
	host := make(map[string]string, len(s.hostTokenToOriginal))
	for k, v := range s.hostTokenToOriginal {
		host[k] = v
	}
	secret := make(map[string]string, len(s.secretTokenToOriginal))
	for k, v := range s.secretTokenToOriginal {
		secret[k] = v
	}
	return TokenMap{
		Version:      MapVersion,
		Tool:         MapTool,
		CreatedAt:    time.Now().UTC().Format(time.RFC3339),
		MaskedSHA256: sha256HexString(masked),
		Host:         host,
		Secret:       secret,
	}
}

func sha256HexString(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func transformByLine(input string, transform func(string) string) string {
	if input == "" {
		return ""
	}
	var out strings.Builder
	start := 0
	for start < len(input) {
		rel := strings.IndexByte(input[start:], '\n')
		line := ""
		newline := ""
		if rel == -1 {
			line = input[start:]
			start = len(input)
		} else {
			pos := start + rel
			line = input[start:pos]
			newline = "\n"
			start = pos + 1
		}
		code, comment := splitCodeAndComment(line)
		out.WriteString(transform(code))
		out.WriteString(comment)
		out.WriteString(newline)
	}
	return out.String()
}

func splitCodeAndComment(line string) (string, string) {
	inSingle := false
	inDouble := false
	inBacktick := false
	escaped := false
	for i := 0; i < len(line); i++ {
		ch := line[i]
		if escaped {
			escaped = false
			continue
		}
		if inDouble {
			if ch == '\\' {
				escaped = true
				continue
			}
			if ch == '"' {
				inDouble = false
			}
			continue
		}
		if inSingle {
			if ch == '\'' {
				if i+1 < len(line) && line[i+1] == '\'' {
					i++
					continue
				}
				inSingle = false
			}
			continue
		}
		if inBacktick {
			if ch == '`' {
				inBacktick = false
			}
			continue
		}
		switch ch {
		case '"':
			inDouble = true
		case '\'':
			inSingle = true
		case '`':
			inBacktick = true
		case '#':
			return line[:i], line[i:]
		}
	}
	return line, ""
}

func LoadTokenMap(path string) (TokenMap, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return TokenMap{}, err
	}
	var m TokenMap
	if err := json.Unmarshal(data, &m); err != nil {
		return TokenMap{}, err
	}
	if m.Host == nil {
		m.Host = map[string]string{}
	}
	if m.Secret == nil {
		m.Secret = map[string]string{}
	}
	return m, nil
}

func SaveTokenMap(path string, m TokenMap) error {
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return os.WriteFile(path, data, 0o644)
}

func CheckMapForUnmask(m TokenMap, inputData []byte) ([]string, error) {
	if len(m.Host) == 0 && len(m.Secret) == 0 {
		return nil, errors.New("selected map has no token mappings")
	}

	warnings := make([]string, 0, 2)
	if tool := strings.TrimSpace(m.Tool); tool != "" && tool != MapTool {
		warnings = append(warnings, "map tool metadata is not clashmask, continuing with token replacement")
	}

	if fp := strings.TrimSpace(m.MaskedSHA256); fp == "" {
		warnings = append(warnings, "map has no content fingerprint; continuing with token replacement")
	} else {
		current := sha256.Sum256(inputData)
		currentHex := hex.EncodeToString(current[:])
		if !strings.EqualFold(fp, currentHex) {
			warnings = append(warnings, "map fingerprint does not match input file; this is expected if content was transformed (e.g. clash -> sing-box)")
		}
	}
	return warnings, nil
}

func UnmaskText(masked string, m TokenMap) string {
	restored, _ := UnmaskTextWithCount(masked, m)
	return restored
}

func UnmaskTextWithCount(masked string, m TokenMap) (string, int) {
	replacements := make([][2]string, 0, len(m.Host)+len(m.Secret))
	for token, origin := range m.Host {
		replacements = append(replacements, [2]string{token, origin})
	}
	for token, origin := range m.Secret {
		replacements = append(replacements, [2]string{token, origin})
	}
	sort.Slice(replacements, func(i, j int) bool {
		return len(replacements[i][0]) > len(replacements[j][0])
	})
	totalReplaced := 0
	out := masked
	for _, pair := range replacements {
		count := strings.Count(out, pair[0])
		if count > 0 {
			totalReplaced += count
			out = strings.ReplaceAll(out, pair[0], pair[1])
		}
	}
	if len(replacements) == 0 {
		return masked, 0
	}
	return out, totalReplaced
}

func parseCSV(input string) []string {
	parts := strings.Split(input, ",")
	result := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			result = append(result, p)
		}
	}
	return result
}

func parseProxyRootStart(code string, indent int) (bool, string) {
	if indent != 0 {
		return false, ""
	}
	m := proxyRootStartRe.FindStringSubmatch(code)
	if len(m) < 2 {
		return false, ""
	}
	if len(m) >= 3 {
		return true, m[2]
	}
	return true, ""
}

func parseSingboxRootStart(code string, globalBraceDepth int) (bool, string) {
	if globalBraceDepth > 1 {
		return false, ""
	}
	m := singboxRootStartRe.FindStringSubmatch(code)
	if len(m) < 2 {
		return false, ""
	}
	if len(m) >= 3 {
		return true, m[2]
	}
	return true, ""
}

func leadingIndentWidth(line string) int {
	n := 0
	for i := 0; i < len(line); i++ {
		switch line[i] {
		case ' ':
			n++
		case '\t':
			n += 4
		default:
			return n
		}
	}
	return n
}

func bracketDeltaIgnoringQuotes(input string) int {
	inSingle := false
	inDouble := false
	escaped := false
	delta := 0
	for i := 0; i < len(input); i++ {
		ch := input[i]
		if escaped {
			escaped = false
			continue
		}
		if inDouble {
			if ch == '\\' {
				escaped = true
				continue
			}
			if ch == '"' {
				inDouble = false
			}
			continue
		}
		if inSingle {
			if ch == '\'' {
				inSingle = false
			}
			continue
		}
		if ch == '"' {
			inDouble = true
			continue
		}
		if ch == '\'' {
			inSingle = true
			continue
		}
		if ch == '[' {
			delta++
		} else if ch == ']' {
			delta--
		}
	}
	return delta
}

func braceDeltaIgnoringQuotes(input string) int {
	inSingle := false
	inDouble := false
	escaped := false
	delta := 0
	for i := 0; i < len(input); i++ {
		ch := input[i]
		if escaped {
			escaped = false
			continue
		}
		if inDouble {
			if ch == '\\' {
				escaped = true
				continue
			}
			if ch == '"' {
				inDouble = false
			}
			continue
		}
		if inSingle {
			if ch == '\'' {
				inSingle = false
			}
			continue
		}
		if ch == '"' {
			inDouble = true
			continue
		}
		if ch == '\'' {
			inSingle = true
			continue
		}
		if ch == '{' {
			delta++
		} else if ch == '}' {
			delta--
		}
	}
	return delta
}

func containerDeltaIgnoringQuotes(input string) int {
	return bracketDeltaIgnoringQuotes(input) + braceDeltaIgnoringQuotes(input)
}
