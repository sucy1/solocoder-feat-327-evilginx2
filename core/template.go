package core

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/kgretzky/evilginx2/log"
)

const (
	TemplateHtml = iota
	TemplateCss
	TemplateJs
	TemplateYaml
	TemplateOther
)

const (
	OpCreate = iota
	OpModify
	OpDelete
	OpRename
)

const (
	sha256PollIntervalWindows = 2 * time.Second
	contextLines              = 3
)

type templateCacheEntry struct {
	content    []byte
	modTime    time.Time
	version    uint64
	parseError error
	sha256     string
}

type TemplateManager struct {
	watcher         *fsnotify.Watcher
	cache           map[string]*templateCacheEntry
	cacheMutex      sync.RWMutex
	watchDirs       map[string]bool
	watchDirsMutex  sync.Mutex
	versionCounter  uint64
	enabled         bool
	debounceTimer   *time.Timer
	debounceDelay   time.Duration
	pendingEvents   map[string]int
	pendingMutex    sync.Mutex
	cfg             *Config
	pollStopCh      chan struct{}
	pollRunning     bool
	pollRunningMtx  sync.Mutex
}

var templateFileExt = map[string]int{
	".html": TemplateHtml,
	".htm":  TemplateHtml,
	".css":  TemplateCss,
	".js":   TemplateJs,
	".yaml": TemplateYaml,
	".yml":  TemplateYaml,
}

type templateError struct {
	File     string
	Line     int
	Column   int
	Message  string
	Context  string
	TypeName string
}

func (e *templateError) Error() string {
	if e.Line > 0 {
		return fmt.Sprintf("%s syntax error in %s at line %d, col %d: %s\n%s",
			e.TypeName, e.File, e.Line, e.Column, e.Message, e.Context)
	}
	return fmt.Sprintf("%s syntax error in %s: %s\n%s",
		e.TypeName, e.File, e.Message, e.Context)
}

func NewTemplateManager(enabled bool, cfg *Config) (*TemplateManager, error) {
	tm := &TemplateManager{
		cache:         make(map[string]*templateCacheEntry),
		watchDirs:     make(map[string]bool),
		enabled:       enabled,
		debounceDelay: 100 * time.Millisecond,
		pendingEvents: make(map[string]int),
		cfg:           cfg,
	}

	if enabled {
		watcher, err := fsnotify.NewWatcher()
		if err != nil {
			return nil, err
		}
		tm.watcher = watcher
		go tm.watchLoop()

		if runtime.GOOS == "windows" {
			tm.pollStopCh = make(chan struct{})
			tm.pollRunning = true
			go tm.sha256PollLoop()
			log.Info("template: Windows SHA256 poll watcher enabled (interval: %v)", sha256PollIntervalWindows)
		}

		log.Info("template hot reload enabled")
	}

	return tm, nil
}

func (tm *TemplateManager) Close() error {
	if tm.watcher != nil {
		tm.watcher.Close()
	}
	tm.pollRunningMtx.Lock()
	if tm.pollRunning {
		close(tm.pollStopCh)
		tm.pollRunning = false
	}
	tm.pollRunningMtx.Unlock()
	return nil
}

func (tm *TemplateManager) AddDirectory(dir string) error {
	if !tm.enabled {
		return nil
	}

	tm.watchDirsMutex.Lock()
	defer tm.watchDirsMutex.Unlock()

	absDir, err := filepath.Abs(dir)
	if err != nil {
		return err
	}

	if tm.watchDirs[absDir] {
		return nil
	}

	err = walkSymlinkAware(absDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		isDir, dirErr := isDirOrSymlinkToDir(path)
		if isDir {
			err := tm.watcher.Add(path)
			if err != nil {
				log.Warning("template: failed to watch directory %s: %v", path, err)
			} else {
				tm.watchDirs[path] = true
				log.Debug("template: watching directory %s", path)
			}
		} else {
			if dirErr == nil {
				tm.preloadFile(path)
			}
		}
		return nil
	})

	if err != nil {
		log.Warning("template: error walking directory %s: %v", absDir, err)
	}

	return nil
}

func computeSHA256(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

func isDirOrSymlinkToDir(path string) (bool, error) {
	info, err := os.Stat(path)
	if err != nil {
		return false, err
	}
	return info.IsDir(), nil
}

func walkSymlinkAware(root string, walkFn filepath.WalkFunc) error {
	return filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return walkFn(path, info, err)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			resolvedPath, err := filepath.EvalSymlinks(path)
			if err != nil {
				return walkFn(path, info, nil)
			}
			resolvedInfo, err := os.Stat(resolvedPath)
			if err != nil {
				return walkFn(path, info, nil)
			}
			if resolvedInfo.IsDir() {
				err := filepath.Walk(resolvedPath, func(subPath string, subInfo os.FileInfo, subErr error) error {
					if subErr != nil {
						return subErr
					}
					rel, relErr := filepath.Rel(resolvedPath, subPath)
					if relErr != nil {
						return relErr
					}
					aliasedPath := filepath.Join(path, rel)
					aliasedInfo := subInfo
					if rel == "." {
						aliasedInfo = info
					}
					return walkFn(aliasedPath, aliasedInfo, nil)
				})
				if err != nil {
					return err
				}
				return filepath.SkipDir
			}
		}
		return walkFn(path, info, nil)
	})
}

func (tm *TemplateManager) preloadFile(path string) {
	ext := strings.ToLower(filepath.Ext(path))
	if _, ok := templateFileExt[ext]; !ok {
		return
	}

	content, err := ioutil.ReadFile(path)
	if err != nil {
		log.Debug("template: failed to preload %s: %v", path, err)
		return
	}

	tm.cacheMutex.Lock()
	tm.versionCounter++
	tm.cache[path] = &templateCacheEntry{
		content: content,
		modTime: time.Now(),
		version: tm.versionCounter,
		sha256:  computeSHA256(content),
	}
	tm.cacheMutex.Unlock()

	log.Debug("template: preloaded %s", path)
}

func (tm *TemplateManager) GetFileContent(path string) ([]byte, error) {
	if tm == nil || !tm.enabled {
		return ioutil.ReadFile(path)
	}

	tm.cacheMutex.RLock()
	entry, ok := tm.cache[path]
	tm.cacheMutex.RUnlock()

	if ok && entry.parseError == nil {
		return entry.content, nil
	}

	if ok && entry.parseError != nil {
		return entry.content, entry.parseError
	}

	content, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	tm.cacheMutex.Lock()
	tm.versionCounter++
	tm.cache[path] = &templateCacheEntry{
		content: content,
		modTime: time.Now(),
		version: tm.versionCounter,
		sha256:  computeSHA256(content),
	}
	tm.cacheMutex.Unlock()

	return content, nil
}

func (tm *TemplateManager) GetFileVersion(path string) uint64 {
	if tm == nil || !tm.enabled {
		return 0
	}

	tm.cacheMutex.RLock()
	defer tm.cacheMutex.RUnlock()

	if entry, ok := tm.cache[path]; ok {
		return entry.version
	}
	return 0
}

func (tm *TemplateManager) watchLoop() {
	for {
		select {
		case event, ok := <-tm.watcher.Events:
			if !ok {
				return
			}
			tm.handleEvent(event)
		case err, ok := <-tm.watcher.Errors:
			if !ok {
				return
			}
			log.Warning("template watcher error: %v", err)
		}
	}
}

func (tm *TemplateManager) sha256PollLoop() {
	log.Debug("template: starting SHA256 poll loop for Windows")
	ticker := time.NewTicker(sha256PollIntervalWindows)
	defer ticker.Stop()

	for {
		select {
		case <-tm.pollStopCh:
			log.Debug("template: SHA256 poll loop stopped")
			return
		case <-ticker.C:
			tm.scanForSHA256Changes()
		}
	}
}

func (tm *TemplateManager) scanForSHA256Changes() {
	tm.watchDirsMutex.Lock()
	dirs := make([]string, 0, len(tm.watchDirs))
	for d := range tm.watchDirs {
		dirs = append(dirs, d)
	}
	tm.watchDirsMutex.Unlock()

	changedFiles := make(map[string]int)

	for _, dir := range dirs {
		walkSymlinkAware(dir, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return nil
			}
			isDir, dirErr := isDirOrSymlinkToDir(path)
			if dirErr == nil && isDir {
				return nil
			}
			if !tm.isWatchedFile(path) {
				return nil
			}

			tm.cacheMutex.RLock()
			cached, exists := tm.cache[path]
			tm.cacheMutex.RUnlock()

			content, err := ioutil.ReadFile(path)
			if err != nil {
				if exists {
					changedFiles[path] = OpDelete
				}
				return nil
			}

			newHash := computeSHA256(content)

			if !exists {
				changedFiles[path] = OpCreate
			} else if cached.sha256 != newHash {
				changedFiles[path] = OpModify
			}
			return nil
		})
	}

	tm.cacheMutex.RLock()
	for cachedPath := range tm.cache {
		if _, stillExists := changedFiles[cachedPath]; stillExists {
			continue
		}
		if _, err := os.Stat(cachedPath); os.IsNotExist(err) {
			changedFiles[cachedPath] = OpDelete
		}
	}
	tm.cacheMutex.RUnlock()

	for path, op := range changedFiles {
		log.Debug("template: SHA256 poll detected change [%d] for %s", op, path)
		tm.pendingMutex.Lock()
		tm.pendingEvents[path] = op
		tm.pendingMutex.Unlock()
	}

	if len(changedFiles) > 0 {
		if tm.debounceTimer != nil {
			tm.debounceTimer.Stop()
		}
		tm.debounceTimer = time.AfterFunc(tm.debounceDelay, tm.processPendingEvents)
	}
}

func (tm *TemplateManager) handleEvent(event fsnotify.Event) {
	if !tm.isWatchedFile(event.Name) {
		if event.Op&fsnotify.Create == fsnotify.Create {
			isDir, dirErr := isDirOrSymlinkToDir(event.Name)
			if dirErr == nil && isDir {
				tm.watchDirsMutex.Lock()
				if !tm.watchDirs[event.Name] {
					err := tm.watcher.Add(event.Name)
					if err == nil {
						tm.watchDirs[event.Name] = true
						log.Debug("template: watching new directory %s", event.Name)
						tm.watchDirsMutex.Unlock()
						_ = walkSymlinkAware(event.Name, func(path string, info os.FileInfo, err error) error {
							if err != nil {
								return nil
							}
							walkIsDir, walkDirErr := isDirOrSymlinkToDir(path)
							if walkDirErr == nil && walkIsDir && path != event.Name {
								tm.watchDirsMutex.Lock()
								if !tm.watchDirs[path] {
									_ = tm.watcher.Add(path)
									tm.watchDirs[path] = true
									log.Debug("template: watching new subdirectory %s", path)
								}
								tm.watchDirsMutex.Unlock()
							} else if walkDirErr == nil && !walkIsDir {
								tm.preloadFile(path)
							}
							return nil
						})
						tm.watchDirsMutex.Lock()
					}
				}
				tm.watchDirsMutex.Unlock()
			}
		}
		return
	}

	var op int
	switch {
	case event.Op&fsnotify.Create == fsnotify.Create:
		op = OpCreate
	case event.Op&fsnotify.Write == fsnotify.Write:
		op = OpModify
	case event.Op&fsnotify.Remove == fsnotify.Remove:
		op = OpDelete
	case event.Op&fsnotify.Rename == fsnotify.Rename:
		op = OpRename
	default:
		return
	}

	tm.pendingMutex.Lock()
	tm.pendingEvents[event.Name] = op
	tm.pendingMutex.Unlock()

	if tm.debounceTimer != nil {
		tm.debounceTimer.Stop()
	}
	tm.debounceTimer = time.AfterFunc(tm.debounceDelay, tm.processPendingEvents)
}

func (tm *TemplateManager) isWatchedFile(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	_, ok := templateFileExt[ext]
	return ok
}

func (tm *TemplateManager) processPendingEvents() {
	tm.pendingMutex.Lock()
	events := make(map[string]int)
	for k, v := range tm.pendingEvents {
		events[k] = v
	}
	tm.pendingEvents = make(map[string]int)
	tm.pendingMutex.Unlock()

	for path, op := range events {
		tm.reloadFile(path, op)
	}
}

func getLineAndColumn(content string, offset int) (int, int) {
	line := 1
	col := 1
	for i := 0; i < offset && i < len(content); i++ {
		if content[i] == '\n' {
			line++
			col = 1
		} else {
			col++
		}
	}
	return line, col
}

func getContextLines(content string, targetLine int, numLines int) string {
	lines := strings.Split(content, "\n")
	start := targetLine - numLines - 1
	if start < 0 {
		start = 0
	}
	end := targetLine + numLines
	if end > len(lines) {
		end = len(lines)
	}

	var ctx strings.Builder
	for i := start; i < end; i++ {
		prefix := "  "
		if i+1 == targetLine {
			prefix = ">>"
		}
		ctx.WriteString(fmt.Sprintf("%s%4d: %s\n", prefix, i+1, lines[i]))
	}
	return ctx.String()
}

func (tm *TemplateManager) reloadFile(path string, op int) {
	ext := strings.ToLower(filepath.Ext(path))
	fileType := templateFileExt[ext]
	typeName := []string{"HTML", "CSS", "JS", "YAML", "Other"}[fileType]

	tm.logAccess(path, op, fileType)

	switch op {
	case OpCreate, OpModify:
		content, err := ioutil.ReadFile(path)
		if err != nil {
			log.Error("template: failed to read %s %s: %v", typeName, path, err)
			return
		}

		newHash := computeSHA256(content)

		parseErr := tm.validateContent(path, content, fileType)

		tm.cacheMutex.Lock()
		existing, hadExisting := tm.cache[path]

		if parseErr != nil {
			log.Error("template: %s parse error in %s:\n%v", typeName, path, parseErr)
			if hadExisting && existing.parseError == nil {
				log.Warning("template: keeping previous valid version (v%d) of %s", existing.version, path)
				existing.modTime = time.Now()
				existing.parseError = parseErr
			} else {
				tm.versionCounter++
				tm.cache[path] = &templateCacheEntry{
					content:    content,
					modTime:    time.Now(),
					version:    tm.versionCounter,
					parseError: parseErr,
					sha256:     newHash,
				}
			}
		} else {
			tm.versionCounter++
			tm.cache[path] = &templateCacheEntry{
				content: content,
				modTime: time.Now(),
				version: tm.versionCounter,
				sha256:  newHash,
			}
			if hadExisting {
				log.Success("template: %s reloaded %s (v%d -> v%d)", typeName, path, existing.version, tm.versionCounter)
			} else {
				log.Success("template: %s loaded %s (v%d)", typeName, path, tm.versionCounter)
			}
		}
		tm.cacheMutex.Unlock()

		if fileType == TemplateYaml {
			tm.reloadPhishlet(path)
		}

	case OpDelete, OpRename:
		tm.cacheMutex.Lock()
		oldEntry, existed := tm.cache[path]
		if existed {
			log.Info("template: %s removed %s (was v%d)", typeName, path, oldEntry.version)
		} else {
			log.Info("template: %s removed %s", typeName, path)
		}
		delete(tm.cache, path)
		tm.cacheMutex.Unlock()
	}
}

func (tm *TemplateManager) validateContent(path string, content []byte, fileType int) error {
	switch fileType {
	case TemplateHtml:
		return tm.validateHTML(path, content)
	case TemplateCss:
		return tm.validateCSS(path, content)
	case TemplateJs:
		return tm.validateJS(path, content)
	case TemplateYaml:
		return tm.validateYAML(path, content)
	}
	return nil
}

func (tm *TemplateManager) validateHTML(path string, content []byte) error {
	str := string(content)
	openTags := regexp.MustCompile(`<([a-zA-Z][a-zA-Z0-9]*)\b[^>]*>`)
	closeTags := regexp.MustCompile(`</([a-zA-Z][a-zA-Z0-9]*)>`)
	selfClosing := []string{"br", "hr", "img", "input", "meta", "link", "area", "base", "col", "embed", "param", "source", "track", "wbr"}

	tagStack := []struct {
		name   string
		offset int
	}{}

	allErrors := []*templateError{}

	openTagPositions := make(map[string][]int)

	for _, m := range openTags.FindAllStringIndex(str, -1) {
		tagMatch := openTags.FindStringSubmatch(str[m[0]:m[1]])
		if len(tagMatch) < 2 {
			continue
		}
		tag := strings.ToLower(tagMatch[1])
		if stringExists(tag, selfClosing) || strings.HasSuffix(str[m[0]:m[1]], "/>") {
			continue
		}
		openTagPositions[tag] = append(openTagPositions[tag], m[0])
		tagStack = append(tagStack, struct {
			name   string
			offset int
		}{tag, m[0]})
	}

	for _, m := range closeTags.FindAllStringIndex(str, -1) {
		tagMatch := closeTags.FindStringSubmatch(str[m[0]:m[1]])
		if len(tagMatch) < 2 {
			continue
		}
		tag := strings.ToLower(tagMatch[1])

		if len(tagStack) > 0 && tagStack[len(tagStack)-1].name == tag {
			tagStack = tagStack[:len(tagStack)-1]
		} else if len(openTagPositions[tag]) > 0 {
			openTagPositions[tag] = openTagPositions[tag][:len(openTagPositions[tag])-1]
		} else {
			line, col := getLineAndColumn(str, m[0])
			allErrors = append(allErrors, &templateError{
				File:     path,
				Line:     line,
				Column:   col,
				TypeName: "HTML",
				Message:  fmt.Sprintf("extra closing tag </%s> without matching opening tag", tag),
				Context:  getContextLines(str, line, contextLines),
			})
		}
	}

	for _, unclosed := range tagStack {
		line, col := getLineAndColumn(str, unclosed.offset)
		allErrors = append(allErrors, &templateError{
			File:     path,
			Line:     line,
			Column:   col,
			TypeName: "HTML",
			Message:  fmt.Sprintf("unclosed tag <%s>", unclosed.name),
			Context:  getContextLines(str, line, contextLines),
		})
	}

	if len(allErrors) > 0 {
		var combinedMsg strings.Builder
		for i, e := range allErrors {
			if i > 0 {
				combinedMsg.WriteString("\n")
			}
			combinedMsg.WriteString(e.Error())
		}
		return fmt.Errorf("%d HTML validation error(s):\n%s", len(allErrors), combinedMsg.String())
	}

	return nil
}

func (tm *TemplateManager) validateCSS(path string, content []byte) error {
	str := string(content)
	braces := 0
	parens := 0
	brackets := 0
	inComment := false
	inString := false
	stringChar := rune(0)
	lastOpenBraceLine := 1
	lastOpenParenLine := 1
	lastOpenBracketLine := 1

	lines := strings.Split(str, "\n")

	for lineIdx, line := range lines {
		lineNum := lineIdx + 1
		inString = false
		stringChar = 0
		for i := 0; i < len(line); i++ {
			ch := line[i]

			if inComment {
				if i+1 < len(line) && line[i] == '*' && line[i+1] == '/' {
					inComment = false
					i++
				}
				continue
			}

			if !inString && i+1 < len(line) && line[i] == '/' && line[i+1] == '*' {
				inComment = true
				i++
				continue
			}

			if inString {
				if ch == '\\' && i+1 < len(line) {
					i++
					continue
				}
				if rune(ch) == stringChar {
					inString = false
				}
				continue
			}

			if ch == '"' || ch == '\'' {
				inString = true
				stringChar = rune(ch)
				continue
			}

			switch ch {
			case '{':
				braces++
				lastOpenBraceLine = lineNum
			case '}':
				braces--
				if braces < 0 {
					return &templateError{
						File:     path,
						Line:     lineNum,
						Column:   i + 1,
						TypeName: "CSS",
						Message:  "extra closing brace '}'",
						Context:  getContextLines(str, lineNum, contextLines),
					}
				}
			case '(':
				parens++
				lastOpenParenLine = lineNum
			case ')':
				parens--
				if parens < 0 {
					return &templateError{
						File:     path,
						Line:     lineNum,
						Column:   i + 1,
						TypeName: "CSS",
						Message:  "extra closing paren ')'",
						Context:  getContextLines(str, lineNum, contextLines),
					}
				}
			case '[':
				brackets++
				lastOpenBracketLine = lineNum
			case ']':
				brackets--
				if brackets < 0 {
					return &templateError{
						File:     path,
						Line:     lineNum,
						Column:   i + 1,
						TypeName: "CSS",
						Message:  "extra closing bracket ']'",
						Context:  getContextLines(str, lineNum, contextLines),
					}
				}
			}
		}
	}

	if braces > 0 {
		return &templateError{
			File:     path,
			Line:     lastOpenBraceLine,
			Column:   1,
			TypeName: "CSS",
			Message:  fmt.Sprintf("%d unclosed brace(s) '{'", braces),
			Context:  getContextLines(str, lastOpenBraceLine, contextLines),
		}
	}
	if parens > 0 {
		return &templateError{
			File:     path,
			Line:     lastOpenParenLine,
			Column:   1,
			TypeName: "CSS",
			Message:  fmt.Sprintf("%d unclosed paren(s) '('", parens),
			Context:  getContextLines(str, lastOpenParenLine, contextLines),
		}
	}
	if brackets > 0 {
		return &templateError{
			File:     path,
			Line:     lastOpenBracketLine,
			Column:   1,
			TypeName: "CSS",
			Message:  fmt.Sprintf("%d unclosed bracket(s) '['", brackets),
			Context:  getContextLines(str, lastOpenBracketLine, contextLines),
		}
	}

	return nil
}

func (tm *TemplateManager) validateJS(path string, content []byte) error {
	str := string(content)
	braces := 0
	brackets := 0
	parens := 0
	inString := false
	stringChar := rune(0)
	escaped := false
	inLineComment := false
	inBlockComment := false

	line := 1
	col := 1
	lastOpenBraceLine := 1
	lastOpenBracketLine := 1
	lastOpenParenLine := 1
	lastOpenBraceCol := 1
	lastOpenBracketCol := 1
	lastOpenParenCol := 1

	for _, ch := range str {
		if inLineComment {
			if ch == '\n' {
				inLineComment = false
				line++
				col = 1
			}
			continue
		}

		if inBlockComment {
			if ch == '*' {
				col++
				continue
			}
			if ch == '/' {
				inBlockComment = false
			}
			if ch == '\n' {
				line++
				col = 1
			} else {
				col++
			}
			continue
		}

		if escaped {
			escaped = false
			col++
			continue
		}

		if ch == '\\' && inString {
			escaped = true
			col++
			continue
		}

		if (ch == '"' || ch == '\'' || ch == '`') && !inString {
			inString = true
			stringChar = ch
			col++
			continue
		}
		if ch == stringChar && inString {
			inString = false
			col++
			continue
		}
		if inString {
			if ch == '\n' {
				if stringChar != '`' {
					return &templateError{
						File:     path,
						Line:     line,
						Column:   col,
						TypeName: "JavaScript",
						Message:  fmt.Sprintf("unterminated string literal (opening at line %d)", line),
						Context:  getContextLines(str, line, contextLines),
					}
				}
				line++
				col = 1
			} else {
				col++
			}
			continue
		}

		if ch == '/' {
			col++
			continue
		}

		switch ch {
		case '\n':
			line++
			col = 1
			continue
		case '{':
			braces++
			lastOpenBraceLine = line
			lastOpenBraceCol = col
		case '}':
			braces--
			if braces < 0 {
				return &templateError{
					File:     path,
					Line:     line,
					Column:   col,
					TypeName: "JavaScript",
					Message:  "extra closing brace '}' - no matching '{'",
					Context:  getContextLines(str, line, contextLines),
				}
			}
		case '[':
			brackets++
			lastOpenBracketLine = line
			lastOpenBracketCol = col
		case ']':
			brackets--
			if brackets < 0 {
				return &templateError{
					File:     path,
					Line:     line,
					Column:   col,
					TypeName: "JavaScript",
					Message:  "extra closing bracket ']' - no matching '['",
					Context:  getContextLines(str, line, contextLines),
				}
			}
		case '(':
			parens++
			lastOpenParenLine = line
			lastOpenParenCol = col
		case ')':
			parens--
			if parens < 0 {
				return &templateError{
					File:     path,
					Line:     line,
					Column:   col,
					TypeName: "JavaScript",
					Message:  "extra closing paren ')' - no matching '('",
					Context:  getContextLines(str, line, contextLines),
				}
			}
		}
		col++
	}

	if inString {
		return &templateError{
			File:     path,
			Line:     line,
			Column:   col,
			TypeName: "JavaScript",
			Message:  "unterminated string literal at end of file",
			Context:  getContextLines(str, line, contextLines),
		}
	}

	if braces > 0 {
		return &templateError{
			File:     path,
			Line:     lastOpenBraceLine,
			Column:   lastOpenBraceCol,
			TypeName: "JavaScript",
			Message:  fmt.Sprintf("%d unclosed brace(s) '{' - missing '}'", braces),
			Context:  getContextLines(str, lastOpenBraceLine, contextLines),
		}
	}
	if brackets > 0 {
		return &templateError{
			File:     path,
			Line:     lastOpenBracketLine,
			Column:   lastOpenBracketCol,
			TypeName: "JavaScript",
			Message:  fmt.Sprintf("%d unclosed bracket(s) '[' - missing ']'", brackets),
			Context:  getContextLines(str, lastOpenBracketLine, contextLines),
		}
	}
	if parens > 0 {
		return &templateError{
			File:     path,
			Line:     lastOpenParenLine,
			Column:   lastOpenParenCol,
			TypeName: "JavaScript",
			Message:  fmt.Sprintf("%d unclosed paren(s) '(' - missing ')'", parens),
			Context:  getContextLines(str, lastOpenParenLine, contextLines),
		}
	}

	return nil
}

func (tm *TemplateManager) validateYAML(path string, content []byte) error {
	pr := regexp.MustCompile(`([a-zA-Z0-9\-\.]*)\.ya?ml`)
	baseMatch := pr.FindStringSubmatch(filepath.Base(path))
	if baseMatch == nil || len(baseMatch) < 2 {
		return nil
	}
	pname := baseMatch[1]
	if pname == "" {
		return nil
	}

	lines := strings.Split(string(content), "\n")

	for lineIdx, line := range lines {
		lineNum := lineIdx + 1
		trimmed := strings.TrimRight(line, " \t")

		if trimmed == "" || strings.HasPrefix(strings.TrimLeft(line, " "), "#") {
			continue
		}

		indent := len(line) - len(strings.TrimLeft(line, " "))

		hasTab := strings.Contains(line[:indent], "\t")
		if hasTab && strings.Contains(line[:indent], " ") {
			return &templateError{
				File:     path,
				Line:     lineNum,
				Column:   indent + 1,
				TypeName: "YAML",
				Message:  "mixed tabs and spaces in indentation",
				Context:  getContextLines(string(content), lineNum, contextLines),
			}
		}

		if indent%2 != 0 {
			log.Warning("template: YAML %s line %d: odd indentation (%d spaces) - YAML typically uses 2-space increments",
				path, lineNum, indent)
		}
	}

	if tm.cfg == nil {
		return nil
	}

	var customParams *map[string]string = nil
	existing, existingErr := tm.cfg.GetPhishlet(pname)
	if existingErr == nil && existing.ParentName != "" {
		customParams = &existing.customParams
	}

	_, phishletErr := NewPhishlet(pname, path, customParams, tm.cfg)
	if phishletErr != nil {
		errMsg := phishletErr.Error()
		errLine := 1

		lineRegex := regexp.MustCompile(`line\s+(\d+)`)
		if m := lineRegex.FindStringSubmatch(errMsg); len(m) >= 2 {
			if n, parseErr := strconv.Atoi(m[1]); parseErr == nil {
				errLine = n
			}
		}

		return &templateError{
			File:     path,
			Line:     errLine,
			Column:   1,
			TypeName: "Phishlet YAML",
			Message:  errMsg,
			Context:  getContextLines(string(content), errLine, contextLines),
		}
	}

	return nil
}

func (tm *TemplateManager) reloadPhishlet(path string) {
	if tm.cfg == nil {
		return
	}

	base := filepath.Base(path)
	pr := regexp.MustCompile(`([a-zA-Z0-9\-\.]*)\.yaml`)
	rpname := pr.FindStringSubmatch(base)
	if rpname == nil || len(rpname) < 2 {
		return
	}

	pname := rpname[1]
	if pname == "" {
		return
	}

	existing, existingErr := tm.cfg.GetPhishlet(pname)

	var customParams *map[string]string = nil
	var parentName string = ""

	if existingErr == nil {
		parentName = existing.ParentName
		if existing.ParentName != "" {
			customParams = &existing.customParams
		}
	}

	newPl, err := NewPhishlet(pname, path, customParams, tm.cfg)
	if err != nil {
		log.Error("template: ──────────────────────────────────────────────")
		if existingErr == nil {
			log.Error("template: FAILED to reload phishlet '%s':", pname)
		} else {
			log.Error("template: FAILED to load new phishlet '%s':", pname)
		}
		errLines := strings.Split(err.Error(), "\n")
		for _, el := range errLines {
			log.Error("template:   %s", el)
		}
		if existingErr == nil {
			log.Error("template: keeping previous valid version of phishlet '%s'", pname)
		}
		log.Error("template: ──────────────────────────────────────────────")
		return
	}

	newPl.ParentName = parentName

	tm.cfg.phishlets[pname] = newPl
	tm.cfg.VerifyPhishlets()

	if existingErr == nil {
		log.Success("template: phishlet '%s' reloaded successfully", pname)
	} else {
		log.Success("template: new phishlet '%s' loaded successfully", pname)
	}
}

func (tm *TemplateManager) logAccess(path string, op int, fileType int) {
	opName := []string{"CREATE", "MODIFY", "DELETE", "RENAME"}[op]
	typeName := []string{"HTML", "CSS", "JS", "YAML", "OTHER"}[fileType]
	now := time.Now().Format("2006-01-02 15:04:05")
	log.Important("[%s] template: %s [%s] %s", now, opName, typeName, path)
}

func (tm *TemplateManager) GetLatestVersion() uint64 {
	if tm == nil || !tm.enabled {
		return 0
	}
	tm.cacheMutex.RLock()
	defer tm.cacheMutex.RUnlock()
	return tm.versionCounter
}
