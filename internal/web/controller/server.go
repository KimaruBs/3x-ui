package controller

import (
	"archive/zip"
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/mhsanaei/3x-ui/v3/internal/database/model"
	"github.com/mhsanaei/3x-ui/v3/internal/logger"
	"github.com/mhsanaei/3x-ui/v3/internal/web/entity"
	"github.com/mhsanaei/3x-ui/v3/internal/web/global"
	"github.com/mhsanaei/3x-ui/v3/internal/web/service"
	"github.com/mhsanaei/3x-ui/v3/internal/web/service/panel"
	"github.com/mhsanaei/3x-ui/v3/internal/web/websocket"

	"github.com/gin-gonic/gin"
)

var filenameRegex = regexp.MustCompile(`^[a-zA-Z0-9_\-.]+$`)

// Константы для управления Xray Bot
const botDir = "xray-bot"

// Глобальная переменная для кэширования удаленной версии бота
var cachedLatestBotVersion string = "unknown"

// ServerController handles server management and status-related operations.
type ServerController struct {
	BaseController

	serverService      service.ServerService
	settingService     service.SettingService
	panelService       panel.PanelService
	xrayMetricsService service.XrayMetricsService
}

// NewServerController creates a new ServerController, initializes routes, and starts background tasks.
func NewServerController(g *gin.RouterGroup) *ServerController {
	a := &ServerController{}
	service.RestoreSystemMetrics()
	a.initRouter(g)
	a.startTask()
	return a
}

// initRouter sets up the routes for server status, Xray management, and utility endpoints.
func (a *ServerController) initRouter(g *gin.RouterGroup) {
	g.GET("/status", a.status)
	g.GET("/cpuHistory/:bucket", a.getCpuHistoryBucket)
	g.GET("/history/:metric/:bucket", a.getMetricHistoryBucket)
	g.GET("/xrayMetricsState", a.getXrayMetricsState)
	g.GET("/xrayMetricsHistory/:metric/:bucket", a.getXrayMetricsHistoryBucket)
	g.GET("/xrayObservatory", a.getXrayObservatory)
	g.GET("/xrayObservatoryHistory/:tag/:bucket", a.getXrayObservatoryHistoryBucket)
	g.GET("/getXrayVersion", a.getXrayVersion)
	g.GET("/getPanelUpdateInfo", a.getPanelUpdateInfo)
	g.GET("/getBotUpdateInfo", a.getBotUpdateInfo)
	g.GET("/getUpdateStatus", a.getUpdateStatus)
	g.GET("/getConfigJson", a.getConfigJson)
	g.GET("/getDb", a.getDb)
	g.GET("/getMigration", a.getMigration)
	g.GET("/getNewUUID", a.getNewUUID)
	g.GET("/getWebCertFiles", a.getWebCertFiles)
	g.GET("/descendants", a.descendants)
	g.GET("/getNewX25519Cert", a.getNewX25519Cert)
	g.GET("/getNewmldsa65", a.getNewmldsa65)
	g.GET("/getNewmlkem768", a.getNewmlkem768)
	g.GET("/getNewVlessEnc", a.getNewVlessEnc)
	g.GET("/clientIps", a.getClientIps)
	g.GET("/fail2banStatus", a.getFail2banStatus)

	g.POST("/stopXrayService", a.stopXrayService)
	g.POST("/restartXrayService", a.restartXrayService)
	g.POST("/installXray/:version", a.installXray)
	g.POST("/updatePanel", a.updatePanel)
	g.POST("/updateBot", a.updateBot) 
	g.POST("/setUpdateChannel", a.setUpdateChannel)
	g.POST("/updateGeofile", a.updateGeofile)
	g.POST("/updateGeofile/:fileName", a.updateGeofile)
	g.POST("/logs/:count", a.getLogs)
	g.POST("/xraylogs/:count", a.getXrayLogs)
	g.POST("/importDB", a.importDB)
	g.POST("/getNewEchCert", a.getNewEchCert)
	g.POST("/getCertHash", a.getCertHash)
	g.POST("/getRemoteCertHash", a.getRemoteCertHash)
	g.POST("/scanRealityTarget", a.scanRealityTarget)
	g.POST("/scanRealityTargets", a.scanRealityTargets)
	g.POST("/clientIps", a.setClientIps)
}

// startTask registers background tasks using a ticker.
func (a *ServerController) startTask() {
	c := global.GetWebServer().GetCron()
	_, _ = c.AddFunc("@every 2s", func() {
		status := a.serverService.RefreshStatus()
		if status == nil {
			return
		}
		a.xrayMetricsService.Sample(time.Now())
		websocket.BroadcastStatus(status)
	})
	_, _ = c.AddFunc("@every 1m", func() {
		if err := service.PersistSystemMetrics(); err != nil {
			logger.Warning("persist system metrics failed:", err)
		}
	})

	// Фоновая проверка версии бота на GitHub каждые 90 секунд (1 минута 30 секунд)
	_, _ = c.AddFunc("@every 1m30s", func() {
		cachedLatestBotVersion = getLatestBotVersion()
	})
}

// status returns the current server status information.
func (a *ServerController) status(c *gin.Context) { jsonObj(c, a.serverService.LastStatus(), nil) }

func (a *ServerController) getFail2banStatus(c *gin.Context) {
	jsonObj(c, a.serverService.GetFail2banStatus(), nil)
}

func parseHistoryBucket(c *gin.Context) (int, bool) {
	bucket, err := strconv.Atoi(c.Param("bucket"))
	if err != nil || bucket <= 0 || !service.IsAllowedHistoryBucket(bucket) {
		jsonMsg(c, "invalid bucket", fmt.Errorf("unsupported bucket"))
		return 0, false
	}
	return bucket, true
}

func (a *ServerController) getCpuHistoryBucket(c *gin.Context) {
	bucket, ok := parseHistoryBucket(c)
	if !ok {
		return
	}
	jsonObj(c, a.serverService.AggregateCpuHistory(bucket, 60), nil)
}

func (a *ServerController) getMetricHistoryBucket(c *gin.Context) {
	metric := c.Param("metric")
	if !slices.Contains(service.SystemMetricKeys, metric) {
		jsonMsg(c, "invalid metric", fmt.Errorf("unknown metric"))
		return
	}
	bucket, ok := parseHistoryBucket(c)
	if !ok {
		return
	}
	jsonObj(c, a.serverService.AggregateSystemMetric(metric, bucket, 60), nil)
}

func (a *ServerController) getXrayMetricsState(c *gin.Context) {
	jsonObj(c, a.xrayMetricsService.State(), nil)
}

func (a *ServerController) getXrayMetricsHistoryBucket(c *gin.Context) {
	metric := c.Param("metric")
	if !slices.Contains(service.XrayMetricKeys, metric) {
		jsonMsg(c, "invalid metric", fmt.Errorf("unknown metric"))
		return
	}
	bucket, ok := parseHistoryBucket(c)
	if !ok {
		return
	}
	jsonObj(c, a.xrayMetricsService.AggregateMetric(metric, bucket, 60), nil)
}

func (a *ServerController) getXrayObservatory(c *gin.Context) {
	jsonObj(c, a.xrayMetricsService.ObservatorySnapshot(), nil)
}

func (a *ServerController) getXrayObservatoryHistoryBucket(c *gin.Context) {
	tag := c.Param("tag")
	if !a.xrayMetricsService.HasObservatoryTag(tag) {
		jsonMsg(c, "invalid tag", fmt.Errorf("unknown observatory tag"))
		return
	}
	bucket, ok := parseHistoryBucket(c)
	if !ok {
		return
	}
	jsonObj(c, a.xrayMetricsService.AggregateObservatory(tag, bucket, 60), nil)
}

func (a *ServerController) getXrayVersion(c *gin.Context) {
	versions, err := a.serverService.GetXrayVersionsCached()
	if err != nil {
		jsonMsg(c, I18nWeb(c, "getVersion"), err)
		return
	}
	jsonObj(c, versions, nil)
}

func (a *ServerController) getPanelUpdateInfo(c *gin.Context) {
	info, err := a.panelService.GetUpdateInfo()
	if err != nil {
		logger.Debug("panel update check failed:", err)
		c.JSON(http.StatusOK, entity.Msg{Success: false})
		return
	}
	jsonObj(c, info, nil)
}

func (a *ServerController) installXray(c *gin.Context) {
	version := c.Param("version")
	err := a.serverService.UpdateXray(version)
	jsonMsg(c, I18nWeb(c, "pages.index.xraySwitchVersionPopover"), err)
}

func (a *ServerController) updatePanel(c *gin.Context) {
	devParam := c.PostForm("dev")
	var runID int64
	var err error
	if devParam == "" {
		runID, err = a.panelService.StartUpdate()
	} else {
		dev, perr := strconv.ParseBool(devParam)
		if perr != nil {
			jsonMsg(c, "invalid data", perr)
			return
		}
		runID, err = a.panelService.StartUpdateChannel(dev)
	}
	var obj any
	if err == nil {
		obj = gin.H{"runId": strconv.FormatInt(runID, 10)}
	}
	jsonMsgObj(c, I18nWeb(c, "pages.index.panelUpdateStartedPopover"), obj, err)
}

func (a *ServerController) getUpdateStatus(c *gin.Context) {
	jsonObj(c, a.panelService.GetUpdateStatus(), nil)
}

func (a *ServerController) setUpdateChannel(c *gin.Context) {
	dev, err := strconv.ParseBool(c.PostForm("dev"))
	if err != nil {
		jsonMsg(c, "invalid data", err)
		return
	}
	err = a.settingService.SetDevChannelEnable(dev)
	jsonMsg(c, I18nWeb(c, "pages.index.updateChannelChanged"), err)
}

func (a *ServerController) updateGeofile(c *gin.Context) {
	fileName := c.Param("fileName")

	if fileName != "" && !a.serverService.IsValidGeofileName(fileName) {
		jsonMsg(c, I18nWeb(c, "pages.index.geofileUpdatePopover"),
			fmt.Errorf("invalid filename: contains unsafe characters or path traversal patterns"))
		return
	}

	err := a.serverService.UpdateGeofile(fileName)
	jsonMsg(c, I18nWeb(c, "pages.index.geofileUpdatePopover"), err)
}

func (a *ServerController) stopXrayService(c *gin.Context) {
	err := a.serverService.StopXrayService()
	if err != nil {
		jsonMsg(c, I18nWeb(c, "pages.xray.stopError"), err)
		websocket.BroadcastXrayState("error", err.Error())
		return
	}
	jsonMsg(c, I18nWeb(c, "pages.xray.stopSuccess"), err)
	websocket.BroadcastXrayState("stop", "")
	websocket.BroadcastNotification(
		I18nWeb(c, "pages.xray.stopSuccess"),
		"Xray service has been stopped",
		"warning",
	)
}

func (a *ServerController) restartXrayService(c *gin.Context) {
	err := a.serverService.RestartXrayService()
	if err != nil {
		jsonMsg(c, I18nWeb(c, "pages.xray.restartError"), err)
		websocket.BroadcastXrayState("error", err.Error())
		return
	}
	jsonMsg(c, I18nWeb(c, "pages.xray.restartSuccess"), err)
	websocket.BroadcastXrayState("running", "")
	websocket.BroadcastNotification(
		I18nWeb(c, "pages.xray.restartSuccess"),
		"Xray service has been restarted successfully",
		"success",
	)
}

func (a *ServerController) getLogs(c *gin.Context) {
	logs := a.serverService.GetLogs(c.Param("count"), c.PostForm("level"), c.PostForm("syslog"))
	jsonObj(c, logs, nil)
}

func (a *ServerController) getXrayLogs(c *gin.Context) {
	freedoms, blackholes := a.serverService.GetDefaultLogOutboundTags()
	logs := a.serverService.GetXrayLogs(
		c.Param("count"),
		c.PostForm("filter"),
		c.PostForm("showDirect"),
		c.PostForm("showBlocked"),
		c.PostForm("showProxy"),
		freedoms,
		blackholes,
	)
	jsonObj(c, logs, nil)
}

func (a *ServerController) getConfigJson(c *gin.Context) {
	configJson, err := a.serverService.GetConfigJson()
	if err != nil {
		jsonMsg(c, I18nWeb(c, "pages.index.getConfigError"), err)
		return
	}
	jsonObj(c, configJson, nil)
}

func (a *ServerController) getDb(c *gin.Context) {
	db, err := a.serverService.GetDb()
	if err != nil {
		jsonMsg(c, I18nWeb(c, "pages.index.getDatabaseError"), err)
		return
	}

	filename := a.serverService.BackupFilename(c.Request.Host)
	if !filenameRegex.MatchString(filename) {
		_ = c.AbortWithError(http.StatusBadRequest, fmt.Errorf("invalid filename"))
		return
	}

	c.Header("Content-Type", "application/octet-stream")
	c.Header("Content-Disposition", "attachment; filename="+filename)
	_, _ = c.Writer.Write(db)
}

func (a *ServerController) getMigration(c *gin.Context) {
	data, filename, err := a.serverService.GetMigration()
	if err != nil {
		jsonMsg(c, I18nWeb(c, "pages.index.getDatabaseError"), err)
		return
	}
	if !filenameRegex.MatchString(filename) {
		_ = c.AbortWithError(http.StatusBadRequest, fmt.Errorf("invalid filename"))
		return
	}

	c.Header("Content-Type", "application/octet-stream")
	c.Header("Content-Disposition", "attachment; filename="+filename)
	_, _ = c.Writer.Write(data)
}

func (a *ServerController) importDB(c *gin.Context) {
	file, _, err := c.Request.FormFile("db")
	if err != nil {
		jsonMsg(c, I18nWeb(c, "pages.index.readDatabaseError"), err)
		return
	}
	defer file.Close()
	if err := a.serverService.ImportDB(file); err != nil {
		jsonMsg(c, I18nWeb(c, "pages.index.importDatabaseError"), err)
		return
	}
	jsonObj(c, I18nWeb(c, "pages.index.importDatabaseSuccess"), nil)
}

func (a *ServerController) descendants(c *gin.Context) {
	data, err := (&service.NodeService{}).LocalDescendants()
	jsonObj(c, data, err)
}

func (a *ServerController) getWebCertFiles(c *gin.Context) {
	certFile, err := a.settingService.GetCertFile()
	if err != nil {
		jsonMsg(c, I18nWeb(c, "somethingWentWrong"), err)
		return
	}
	keyFile, err := a.settingService.GetKeyFile()
	if err != nil {
		jsonMsg(c, I18nWeb(c, "somethingWentWrong"), err)
		return
	}
	jsonObj(c, gin.H{"webCertFile": certFile, "webKeyFile": keyFile}, nil)
}

func (a *ServerController) getNewX25519Cert(c *gin.Context) {
	cert, err := a.serverService.GetNewX25519Cert()
	if err != nil {
		jsonMsg(c, I18nWeb(c, "pages.inbounds.toasts.getNewX25519CertError"), err)
		return
	}
	jsonObj(c, cert, nil)
}

func (a *ServerController) getNewmldsa65(c *gin.Context) {
	cert, err := a.serverService.GetNewmldsa65()
	if err != nil {
		jsonMsg(c, I18nWeb(c, "pages.inbounds.toasts.getNewmldsa65Error"), err)
		return
	}
	jsonObj(c, cert, nil)
}

func (a *ServerController) getNewEchCert(c *gin.Context) {
	cert, err := a.serverService.GetNewEchCert(c.PostForm("sni"))
	if err != nil {
		jsonMsg(c, "get ech certificate", err)
		return
	}
	jsonObj(c, cert, nil)
}

func (a *ServerController) getCertHash(c *gin.Context) {
	hashes, err := a.serverService.GetCertHash(c.PostForm("certFile"), c.PostForm("certContent"))
	if err != nil {
		jsonMsg(c, "get cert hash", err)
		return
	}
	jsonObj(c, hashes, nil)
}

func (a *ServerController) getRemoteCertHash(c *gin.Context) {
	hashes, err := a.serverService.GetRemoteCertHash(c.PostForm("server"))
	if err != nil {
		jsonMsg(c, "get remote cert hash", err)
		return
	}
	jsonObj(c, hashes, nil)
}

func (a *ServerController) scanRealityTarget(c *gin.Context) {
	res, err := a.serverService.ScanRealityTarget(c.PostForm("target"))
	if err != nil {
		jsonMsg(c, I18nWeb(c, "pages.inbounds.toasts.scanRealityTargetError"), err)
		return
	}
	jsonObj(c, res, nil)
}

func (a *ServerController) scanRealityTargets(c *gin.Context) {
	res, err := a.serverService.ScanRealityTargets(c.PostForm("targets"))
	if err != nil {
		jsonMsg(c, I18nWeb(c, "pages.inbounds.toasts.scanRealityTargetError"), err)
		return
	}
	jsonObj(c, res, nil)
}

func (a *ServerController) getNewVlessEnc(c *gin.Context) {
	out, err := a.serverService.GetNewVlessEnc()
	if err != nil {
		jsonMsg(c, I18nWeb(c, "pages.inbounds.toasts.getNewVlessEncError"), err)
		return
	}
	jsonObj(c, out, nil)
}

func (a *ServerController) getNewUUID(c *gin.Context) {
	uuidResp, err := a.serverService.GetNewUUID()
	if err != nil {
		jsonMsg(c, "Failed to generate UUID", err)
		return
	}
	jsonObj(c, uuidResp, nil)
}

func (a *ServerController) getNewmlkem768(c *gin.Context) {
	out, err := a.serverService.GetNewmlkem768()
	if err != nil {
		jsonMsg(c, "Failed to generate mlkem768 keys", err)
		return
	}
	jsonObj(c, out, nil)
}

func (a *ServerController) getClientIps(c *gin.Context) {
	ips, err := (&service.InboundService{}).GetAllInboundClientIps()
	jsonObj(c, ips, err)
}

func (a *ServerController) setClientIps(c *gin.Context) {
	var ips []model.InboundClientIps
	if err := c.ShouldBindJSON(&ips); err != nil {
		jsonMsg(c, "invalid data", err)
		return
	}
	err := (&service.InboundService{}).MergeInboundClientIps(ips)
	jsonMsg(c, "Client IPs merged", err)
}

// Вспомогательная функция для очистки строки версии (оставляет только цифры и точки)
func cleanVersionString(v string) string {
	v = strings.TrimSpace(v)
	re := regexp.MustCompile(`^v?([0-9.]+)`)
	matches := re.FindStringSubmatch(v)
	if len(matches) > 1 {
		return matches[1]
	}
	return v
}

// getLatestBotVersion качает текстовый файл версии напрямую из репозитория KimaruBs
func getLatestBotVersion() string {
	url := "https://raw.githubusercontent.com/KimaruBs/3x-ui/refs/heads/main/xray-bot/version"

	client := http.Client{Timeout: 5 * time.Second}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "unknown"
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)")

	resp, err := client.Do(req)
	if err != nil {
		return "unknown"
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "unknown"
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "unknown"
	}

	return cleanVersionString(string(body))
}

// getBotUpdateInfo проверяет статус установки и сравнивает цифровые версии Xray Bot
func (a *ServerController) getBotUpdateInfo(c *gin.Context) {
	execPath, err := os.Executable()
	if err != nil {
		logger.Error("Не удалось определить путь исполняемого файла панели:", err)
		c.JSON(http.StatusOK, gin.H{"success": false, "msg": "Internal server error"})
		return
	}
	
	baseDir := filepath.Dir(execPath)
	absoluteBotDir := filepath.Join(baseDir, botDir)
	absoluteVersionFile := filepath.Join(absoluteBotDir, "version")

	if _, err := os.Stat(absoluteBotDir); os.IsNotExist(err) {
		c.JSON(http.StatusOK, gin.H{
			"success": true,
			"obj": gin.H{
				"installed":       false,
				"currentVersion":  "",
				"latestVersion":   "remote",
				"updateAvailable": false,
			},
		})
		return
	}

	rawLocalVer := ""

	// Читаем файл 'version' из папки бота по абсолютному пути
	if data, err := os.ReadFile(absoluteVersionFile); err == nil {
		rawLocalVer = strings.TrimSpace(string(data))
	}

	// Дефолтный фоллбэк
	if rawLocalVer == "" {
		rawLocalVer = "1.0.0"
	}

	currentVer := cleanVersionString(rawLocalVer)

	if cachedLatestBotVersion == "unknown" {
		cachedLatestBotVersion = getLatestBotVersion()
	}

	updateAvailable := cachedLatestBotVersion != "unknown" && currentVer != cachedLatestBotVersion

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"obj": gin.H{
			"installed":       true,
			"currentVersion":  rawLocalVer,            
			"latestVersion":   cachedLatestBotVersion, 
			"updateAvailable": updateAvailable,
		},
	})
}

// updateBot скачивает свежий архив файлов бота напрямую с GitHub на чистом Go и обновляет его (Cross-platform)
func (a *ServerController) updateBot(c *gin.Context) {
	execPath, err := os.Executable()
	if err != nil {
		logger.Error("Update bot failed: cannot determine executable path:", err)
		c.JSON(http.StatusOK, gin.H{"success": false, "msg": "Internal path error"})
		return
	}
	
	baseDir := filepath.Dir(execPath)
	absoluteBotDir := filepath.Join(baseDir, botDir)

	logger.Info("Запуск кроссплатформенного обновления бота на чистом Go...")

	// 1. Скачиваем ZIP архив в память
	archiveURL := "https://github.com/KimaruBs/3x-ui/archive/refs/heads/main.zip"
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(archiveURL)
	if err != nil {
		logger.Error("Failed to download bot archive:", err)
		c.JSON(http.StatusOK, gin.H{"success": false, "msg": "Download failed: " + err.Error()})
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		c.JSON(http.StatusOK, gin.H{"success": false, "msg": "Download failed with status: " + resp.Status})
		return
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"success": false, "msg": "Read archive failed: " + err.Error()})
		return
	}

	// 2. Распаковываем ZIP-архив на лету средствами Go
	zipReader, err := zip.NewReader(bytes.NewReader(bodyBytes), int64(len(bodyBytes)))
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"success": false, "msg": "Parse ZIP failed: " + err.Error()})
		return
	}

	// Префикс пути, который GitHub создает внутри архива, и целевая папка внутри репозитория
	targetPrefix := "3x-ui-main/xray-bot/"

	// Гарантируем, что папка бота существует перед записью файлов
	if err := os.MkdirAll(absoluteBotDir, 0755); err != nil {
		c.JSON(http.StatusOK, gin.H{"success": false, "msg": "Create directory failed: " + err.Error()})
		return
	}

	for _, file := range zipReader.File {
		// Проверяем, относится ли файл к нужной подпапке xray-bot
		if !strings.HasPrefix(file.Name, targetPrefix) {
			continue
		}

		// Вычисляем относительный путь внутри папки xray-bot
		relPath := strings.TrimPrefix(file.Name, targetPrefix)
		if relPath == "" {
			continue
		}

		// Формируем финальный абсолютный путь на сервере
		outPath := filepath.Join(absoluteBotDir, relPath)

		// Если это директория, создаем её
		if file.FileInfo().IsDir() {
			if err := os.MkdirAll(outPath, 0755); err != nil {
				c.JSON(http.StatusOK, gin.H{"success": false, "msg": "Create internal folder failed: " + err.Error()})
				return
			}
			continue
		}

		// Создаем родительские папки для файлов на случай, если они еще не созданы
		if err := os.MkdirAll(filepath.Dir(outPath), 0755); err != nil {
			c.JSON(http.StatusOK, gin.H{"success": false, "msg": "Create parent subfolders failed: " + err.Error()})
			return
		}

		// Открываем файл из архива и перезаписываем его на диске
		rc, err := file.Open()
		if err != nil {
			c.JSON(http.StatusOK, gin.H{"success": false, "msg": "Open zipped file failed: " + err.Error()})
			return
		}

		outFile, err := os.OpenFile(outPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, file.Mode())
		if err != nil {
			rc.Close()
			c.JSON(http.StatusOK, gin.H{"success": false, "msg": "Write unpacked file failed: " + err.Error()})
			return
		}

		_, err = io.Copy(outFile, rc)
		outFile.Close()
		rc.Close()
		if err != nil {
			c.JSON(http.StatusOK, gin.H{"success": false, "msg": "Copy unpacked data failed: " + err.Error()})
			return
		}
	}

	logger.Info("Архив успешно распакован на чистом Go. Установка зависимостей и перезапуск...")

	// 3. Выполняем установку зависимостей pip и перезапуск в зависимости от операционной системы
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	var pipCmd *exec.Cmd
	var restartCmd *exec.Cmd

	// Проверяем, есть ли venv
	venvPip := filepath.Join(absoluteBotDir, "venv", "bin", "pip")
	if _, err := os.Stat(filepath.Join(absoluteBotDir, "venv", "Scripts", "pip.exe")); err == nil {
		venvPip = filepath.Join(absoluteBotDir, "venv", "Scripts", "pip.exe")
	}

	hasVenv := false
	if _, err := os.Stat(venvPip); err == nil {
		hasVenv = true
	}

	// Проверяем операционную систему на этапе выполнения панели
	if filepath.Separator == '\\' {
		// WINDOWS ENVIRONMENT
		reqPath := filepath.Join(absoluteBotDir, "requirements.txt")
		if hasVenv {
			pipCmd = exec.CommandContext(ctx, "cmd", "/c", fmt.Sprintf(`"%s" install -r "%s"`, venvPip, reqPath))
		} else {
			pipCmd = exec.CommandContext(ctx, "cmd", "/c", fmt.Sprintf(`pip install -r "%s"`, reqPath))
		}
		// На винде просто пытаемся дёрнуть nssm, службу или батник, если они завязаны
		restartCmd = exec.CommandContext(ctx, "cmd", "/c", "net stop xray-bot && net start xray-bot")
	} else {
		// LINUX / UNIX ENVIRONMENT (Любые дистрибутивы: Ubuntu, Debian, Alpine, CentOS и т.д.)
		reqPath := filepath.Join(absoluteBotDir, "requirements.txt")
		if hasVenv {
			pipCmd = exec.CommandContext(ctx, "sh", "-c", fmt.Sprintf(`"%s" install -r "%s"`, venvPip, reqPath))
		} else {
			pipCmd = exec.CommandContext(ctx, "sh", "-c", fmt.Sprintf(`pip install -r "%s"`, reqPath))
		}

		// Универсальный перезапуск демона Linux с проверкой на наличие systemctl
		restartCmd = exec.CommandContext(ctx, "sh", "-c", "if command -v systemctl >/dev/null 2>&1; then sudo systemctl restart xray-bot || systemctl restart xray-bot; fi")
	}

	// Запускаем pip install
	if pipOut, err := pipCmd.CombinedOutput(); err != nil {
		logger.Warning("Pip install finished with notice/error:", err, string(pipOut))
	}

	// Перезапускаем службу
	var restartMsg string
	if restartOut, err := restartCmd.CombinedOutput(); err != nil {
		restartMsg = "Обновлено, но не удалось перезапустить службу (возможно служба не настроена): " + err.Error()
		logger.Warning(restartMsg, string(restartOut))
	} else {
		restartMsg = "Бот успешно обновлен и перезапущен."
		logger.Info(restartMsg)
	}

	// Обнуляем кэш версии
	cachedLatestBotVersion = "unknown"
	
	// Возвращаем обновленный статус в UI
	a.getBotUpdateInfo(c)
}
