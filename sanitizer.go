package main

import (
	"encoding/json"
	"errors"
	"os"
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

type Config struct {
	HostKeys   []string
	SecretKeys []string
}

type TokenMap struct {
	Version   int               `json:"version"`
	CreatedAt string            `json:"created_at"`
	Host      map[string]string `json:"host"`
	Secret    map[string]string `json:"secret"`
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
	// 1: key+separator, 2: entire value, 3: "value", 4: 'value', 5: unquoted value
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
	return transformByLine(input, func(code string) string {
		masked := code
		masked = s.replaceKV(masked, s.secretKVRe, s.secretToken)
		masked = s.replaceKV(masked, s.hostKVRe, s.hostToken)
		masked = s.replaceURICredentials(masked)
		masked = s.replaceURIHosts(masked)
		return masked
	})
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

func (s *Sanitizer) ExportMap() TokenMap {
	host := make(map[string]string, len(s.hostTokenToOriginal))
	for k, v := range s.hostTokenToOriginal {
		host[k] = v
	}
	secret := make(map[string]string, len(s.secretTokenToOriginal))
	for k, v := range s.secretTokenToOriginal {
		secret[k] = v
	}
	return TokenMap{
		Version:   1,
		CreatedAt: time.Now().UTC().Format(time.RFC3339),
		Host:      host,
		Secret:    secret,
	}
}

func transformByLine(input string, transform func(code string) string) string {
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

func splitCodeAndComment(line string) (code string, comment string) {
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

func UnmaskText(masked string, m TokenMap) string {
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
	flat := make([]string, 0, len(replacements)*2)
	for _, pair := range replacements {
		flat = append(flat, pair[0], pair[1])
	}
	if len(flat) == 0 {
		return masked
	}
	return strings.NewReplacer(flat...).Replace(masked)
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
