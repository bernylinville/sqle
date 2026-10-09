package v1

import (
	"errors"
	"fmt"
	"strings"

	"github.com/actiontech/dms/pkg/dms-common/pkg/secretkey"
)

// login config
var (
	JwtSigningKey = []byte("secret")
)

// router
var (
	SessionRouterGroup            = "/dms/sessions"
	UserRouterGroup               = "/dms/users"
	DBServiceRouterGroup          = "/dms/projects/:project_uid/db_services"
	DBEnvironmentTagGroup         = "/dms/projects/:project_uid/environment_tags"
	OpsTypeRouterGroup            = "/dms/projects/:project_uid/ops_types"
	ProxyRouterGroup              = "/dms/proxys"
	PluginRouterGroup             = "/dms/plugins"
	MemberRouterGroup             = "/dms/projects/:project_uid/members"
	MemberGroupRouterGroup        = "/dms/projects/:project_uid/member_groups"
	ProjectRouterGroup            = "/dms/projects"
	NotificationRouterGroup       = "/dms/notifications"
	WebHookRouterGroup            = "/dms/webhooks"
	MemberForInternalRouterSuffix = "/internal"
	InternalDBServiceRouterGroup  = "/internal/db_services"
	LicenseRouterGroup            = "/dms/license"
)

// api group
var (
	GroupV1             = "/v1"
	CurrentGroupVersion = GroupV1
)

// ResetJWTSigningKey replaces the JWT signing key with a 32-byte key derived
// from the given root secret via HKDF-SHA256 (domain InfoJWT), instead of
// using the raw configured secret. See CVE-2025-15107 / GHSA-43h9-hc38-qph5.
func ResetJWTSigningKey(val string) error {
	if val == "" {
		return errors.New("reset jwt signing key: empty secret_key")
	}

	derivedKey, err := secretkey.DeriveKey(val, secretkey.InfoJWT)
	if err != nil {
		return err
	}

	JwtSigningKey = derivedKey
	return nil
}

func GetUserOpPermissionRouter(userUid string) string {
	return fmt.Sprintf("%s%s/%s/op_permission", CurrentGroupVersion, UserRouterGroup, userUid)
}

func GetUserOpPermissionRouterWithoutPrefix(userUid string) string {
	router := GetUserOpPermissionRouter(userUid)
	return strings.TrimPrefix(strings.TrimPrefix(router, CurrentGroupVersion), UserRouterGroup)
}

func GetDBServiceRouter(projectUid string) string {
	return fmt.Sprintf("%s%s", CurrentGroupVersion, strings.Replace(DBServiceRouterGroup, ":project_uid", projectUid, 1))
}

func GetUserRouter(userUid string) string {
	return fmt.Sprintf("%s%s/%s", CurrentGroupVersion, UserRouterGroup, userUid)
}

func GetMemberGroupRouter(memberGroupUid, projectUid string) string {
	return fmt.Sprintf("%s%s/%s", CurrentGroupVersion, strings.Replace(MemberGroupRouterGroup, ":project_uid", projectUid, 1), memberGroupUid)
}

func GetUsersRouter() string {
	return fmt.Sprintf("%s%s", CurrentGroupVersion, UserRouterGroup)
}

func GetListMembersForInternalRouter(projectUid string) string {
	return fmt.Sprintf("%s%s%s", CurrentGroupVersion, strings.Replace(MemberRouterGroup, ":project_uid", projectUid, 1), MemberForInternalRouterSuffix)
}

func GetProxyRouter() string {
	return fmt.Sprintf("%s%s", CurrentGroupVersion, ProxyRouterGroup)
}

func GetPluginRouter() string {
	return fmt.Sprintf("%s%s", CurrentGroupVersion, PluginRouterGroup)
}

func GetProjectsRouter() string {
	return fmt.Sprintf("%s%s", CurrentGroupVersion, ProjectRouterGroup)
}

func GetNotificationRouter() string {
	return fmt.Sprintf("%s%s", CurrentGroupVersion, NotificationRouterGroup)
}

func GetWebHooksRouter() string {
	return fmt.Sprintf("%s%s", CurrentGroupVersion, WebHookRouterGroup)
}

func GetDBConnectionAbleRouter() string {
	return fmt.Sprintf("%s%s/connection", CurrentGroupVersion, InternalDBServiceRouterGroup)
}

func GetGlobalDataExportWorkflowsRouter() string {
	return fmt.Sprintf("%s%s", CurrentGroupVersion, "/dms/dashboard/data_export_workflows")
}

func GetOpsTypesRouter(projectUid string) string {
	return fmt.Sprintf("%s%s", CurrentGroupVersion, strings.Replace(OpsTypeRouterGroup, ":project_uid", projectUid, 1))
}
