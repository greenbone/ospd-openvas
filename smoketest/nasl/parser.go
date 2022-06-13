package nasl

import (
	"bufio"
	"bytes"
	"io"
	"path/filepath"
	"strings"
	"sync"
)

type Plugin struct {
	Path               string
	OID                string
	Family             string
	Plugins            []string
	ScriptDependencies []string
}

type Token int

const (
	UNKNOWN Token = iota
	EOF
	WS      //  \t\n
	QT      // "'
	LP      // (
	RP      // )
	LB      // [
	RB      // ]
	CLB     // {
	CRB     // }
	C       // ,
	SC      // ;
	DP      // :
	KEYWORD //keyword are non special character
)

var eof = rune(0)

func isWhitespace(ch rune) bool {
	return ch == ' ' || ch == '\t' || ch == '\n'
}

func isKeywordComp(ch rune) bool {
	return (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || ch == '-' || ch == '_'
}

type Scanner struct {
	r *bufio.Reader
}

func NewScanner(r io.Reader) *Scanner {
	return &Scanner{r: bufio.NewReader(r)}
}

func (s *Scanner) read() rune {
	ch, _, err := s.r.ReadRune()
	if err != nil {
		return eof
	}
	return ch
}

func (s *Scanner) unread() { _ = s.r.UnreadRune() }

func (s *Scanner) skip(result Token, verify func(rune) bool) (Token, string) {
	var buf bytes.Buffer
	buf.WriteRune(s.read())
	for {
		if ch := s.read(); ch == eof {
			break
		} else if !verify(ch) {
			s.unread()
			break
		} else {
			buf.WriteRune(ch)
		}
	}
	return result, buf.String()
}

func (s *Scanner) skipWS() (Token, string) {
	return s.skip(WS, isWhitespace)
}

func (s *Scanner) skipNonSpecial() (Token, string) {
	return s.skip(KEYWORD, isKeywordComp)
}

func (s *Scanner) Scan() (Token, string) {
	ch := s.read()
	if isWhitespace(ch) {
		s.unread()
		return s.skip(WS, isWhitespace)
	}
	if isKeywordComp(ch) {
		s.unread()
		return s.skip(KEYWORD, isKeywordComp)
	}
	switch ch {
	case eof:
		return EOF, ""
	case '\'':
		return QT, string(ch)
	case '"':
		return QT, string(ch)
	case '(':
		return LP, string(ch)
	case ')':
		return RP, string(ch)
	case '[':
		return LB, string(ch)
	case ']':
		return RB, string(ch)
	case '{':
		return CLB, string(ch)
	case '}':
		return CRB, string(ch)
	case ',':
		return C, string(ch)
	case ';':
		return SC, string(ch)
	case ':':
		return DP, string(ch)

	default:
		return UNKNOWN, string(ch)
	}

}

func skipWS(scanner *Scanner) (t Token, s string) {
	for {
		t, s = scanner.Scan()
		if t != WS {
			return
		}
	}
}

type PluginCache struct {
	sync.RWMutex
	plugins []string
}

func (pc *PluginCache) Append(s ...string) {
	pc.Lock()
	pc.plugins = append(pc.plugins, s...)
	pc.Unlock()
}

func (pc *PluginCache) Get() []string {
	pc.RLock()
	result := pc.plugins
	pc.RUnlock()
	return result
}

func StringArgument(scanner *Scanner) (string, bool) {
	var buf bytes.Buffer
	t, i := skipWS(scanner)
	if t == QT {

		for {
			t, i = scanner.Scan()
			if t == EOF {
				break
			}

			if t == QT {
				return buf.String(), true
			}

			buf.WriteString(i)
		}
	}
	return "", false
}

func singleAnonStringArgumentFunction(scanner *Scanner) (string, bool) {
	t, _ := skipWS(scanner)
	if t == LP {
		if arg, ok := StringArgument(scanner); ok {
			t, _ = skipWS(scanner)
			if t == RP {
				t, _ = skipWS(scanner)
				if t == SC {
					return arg, true
				}
			}
		}
	}
	return "", false
}

func multipleAnonStringArgumentFunction(scanner *Scanner) ([]string, bool) {
	result := make([]string, 0)
	t, _ := skipWS(scanner)
	if t == LP {
		for {
			if arg, ok := StringArgument(scanner); ok {
				t, _ = skipWS(scanner)
				if t == RP {
					t, _ = skipWS(scanner)
					if t == SC {
						result = append(result, arg)
						return result, true
					}
				}
				if t == C {
					result = append(result, arg)
					continue
				}
				if t != C || t == EOF {
					break
				}
			} else {
				break
			}
		}
	}
	return result, false
}

func Parse(source, path string, input io.Reader) Plugin {
	// We currently assume that each nasl script has a
	// if (description) { }
	// block so that we don't have to care about && ||
	// As of 2022-06-03 there are no cases where script_oid or script_family contain anything but a string
	// to make things easier we just asssume that so tat we don't have to do a loopup for a variable
	oid := ""
	family := ""
	plugins := make([]string, 0)
	script_dependencies := make([]string, 0)
	scanner := NewScanner(input)
	appendPluginPath := func(arg string, cache *[]string) {
		ip := filepath.Join(source, arg)
		*cache = append(*cache, ip)
	}
	for {
		t, i := scanner.Scan()
		if t == EOF {
			break
		}
		if t == KEYWORD {
			switch i {
			case "script_oid":
				if arg, ok := singleAnonStringArgumentFunction(scanner); ok {
					// TODO check if already parsed via cache and return
					oid = arg
				}
			case "script_family":
				if arg, ok := singleAnonStringArgumentFunction(scanner); ok {
					family = arg
				}
			case "script_dependencies":
				if args, ok := multipleAnonStringArgumentFunction(scanner); ok {
					for _, i := range args {
						// there are some instances that call script_dependencies("a.nasl, b.nasl");
						// instead of script_dependencies("a.nasl", "b.nasl");
						split := strings.Split(i, ",")
						for _, j := range split {
							appendPluginPath(strings.Trim(j, " "), &script_dependencies)
						}
					}
				}
			case "include":
				if arg, ok := singleAnonStringArgumentFunction(scanner); ok {
					appendPluginPath(arg, &plugins)
				}
			}

		}

	}
	return Plugin{
		Path:               path,
		OID:                oid,
		Family:             family,
		Plugins:            plugins,
		ScriptDependencies: script_dependencies,
	}

}
