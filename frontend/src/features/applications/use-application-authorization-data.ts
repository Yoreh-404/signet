import {
  useCallback,
  useEffect,
  useState,
  type Dispatch,
  type SetStateAction,
} from "react";

import * as applicationAuthorizationApi from "../../lib/api/application-authorization";
import type {
  ApplicationAuthorizationPreview,
  ApplicationAuthorizationProfile,
  ApplicationAuthorizationSubjects,
  ApplicationPermissionDefinition,
  ApplicationPermissionOverride,
  ApplicationProfileRole,
} from "../../lib/api/application-authorization";
import {
  reconcileAuthorizationBindings,
  type AuthorizationBindingScope,
  type AuthorizationBindingSnapshot,
} from "./authorization-bindings-service";
import type { ApplicationWorkspaceRequestApi } from "./use-application-workspace-request-context";

export type ApplicationAuthorizationBindings = {
  userRoleIds: string[];
  setUserRoleIds: Dispatch<SetStateAction<string[]>>;
  groupRoleIds: string[];
  setGroupRoleIds: Dispatch<SetStateAction<string[]>>;
  organizationRoleIds: Record<string, string[]>;
  setOrganizationRoleIds: Dispatch<SetStateAction<Record<string, string[]>>>;
  userPermissionOverrides: ApplicationPermissionOverride[];
  setUserPermissionOverrides: Dispatch<SetStateAction<ApplicationPermissionOverride[]>>;
  authorizationPreview: ApplicationAuthorizationPreview | null;
  setAuthorizationPreview: Dispatch<SetStateAction<ApplicationAuthorizationPreview | null>>;
  authorizationLoading: boolean;
  setAuthorizationLoading: Dispatch<SetStateAction<boolean>>;
  authorizationFeedback: string;
  setAuthorizationFeedback: Dispatch<SetStateAction<string>>;
  authorizationBindingsDirty: boolean;
  setAuthorizationBindingsDirty: Dispatch<SetStateAction<boolean>>;
  applyAuthorizationBindingSnapshot: (snapshot: AuthorizationBindingSnapshot) => void;
  resetAuthorizationBindings: () => void;
  updateUserRoleIds: (
    next: string[] | ((current: string[]) => string[]),
  ) => void;
  updateGroupRoleIds: (
    next: string[] | ((current: string[]) => string[]),
  ) => void;
  updateOrganizationRoleIds: (
    next:
      | Record<string, string[]>
      | ((current: Record<string, string[]>) => Record<string, string[]>),
  ) => void;
  updateUserPermissionOverrides: (
    next:
      | ApplicationPermissionOverride[]
      | ((current: ApplicationPermissionOverride[]) => ApplicationPermissionOverride[]),
  ) => void;
};

export type ApplicationAuthorizationData = {
  authorizationProfiles: ApplicationAuthorizationProfile[];
  setAuthorizationProfiles: Dispatch<SetStateAction<ApplicationAuthorizationProfile[]>>;
  selectedAuthorizationProfileId: string;
  setSelectedAuthorizationProfileId: Dispatch<SetStateAction<string>>;
  applicationRoles: ApplicationProfileRole[];
  setApplicationRoles: Dispatch<SetStateAction<ApplicationProfileRole[]>>;
  applicationPermissionCatalog: ApplicationPermissionDefinition[];
  setApplicationPermissionCatalog: Dispatch<SetStateAction<ApplicationPermissionDefinition[]>>;
  authorizationSubjects: ApplicationAuthorizationSubjects | null;
  setAuthorizationSubjects: Dispatch<SetStateAction<ApplicationAuthorizationSubjects | null>>;
  selectedAuthorizationUserId: string;
  setSelectedAuthorizationUserId: Dispatch<SetStateAction<string>>;
  selectedAuthorizationGroupId: string;
  setSelectedAuthorizationGroupId: Dispatch<SetStateAction<string>>;
  bindings: ApplicationAuthorizationBindings;
};

export function useApplicationAuthorizationData({
  applicationId,
  saveFailed,
  requestContext,
}: {
  applicationId: string;
  saveFailed: string;
  requestContext: ApplicationWorkspaceRequestApi;
}): ApplicationAuthorizationData {
  const [authorizationProfiles, setAuthorizationProfiles] = useState<ApplicationAuthorizationProfile[]>([]);
  const [selectedAuthorizationProfileId, setSelectedAuthorizationProfileId] = useState("");
  const [applicationRoles, setApplicationRoles] = useState<ApplicationProfileRole[]>([]);
  const [applicationPermissionCatalog, setApplicationPermissionCatalog] = useState<ApplicationPermissionDefinition[]>([]);
  const [authorizationSubjects, setAuthorizationSubjects] = useState<ApplicationAuthorizationSubjects | null>(null);
  const [selectedAuthorizationUserId, setSelectedAuthorizationUserId] = useState("");
  const [selectedAuthorizationGroupId, setSelectedAuthorizationGroupId] = useState("");
  const [userRoleIds, setUserRoleIds] = useState<string[]>([]);
  const [groupRoleIds, setGroupRoleIds] = useState<string[]>([]);
  const [organizationRoleIds, setOrganizationRoleIds] = useState<Record<string, string[]>>({});
  const [userPermissionOverrides, setUserPermissionOverrides] = useState<ApplicationPermissionOverride[]>([]);
  const [authorizationPreview, setAuthorizationPreview] = useState<ApplicationAuthorizationPreview | null>(null);
  const [authorizationLoading, setAuthorizationLoading] = useState(false);
  const [authorizationFeedback, setAuthorizationFeedback] = useState("");
  const [authorizationBindingsDirty, setAuthorizationBindingsDirty] = useState(false);

  const applyAuthorizationBindingSnapshot = useCallback(
    (snapshot: AuthorizationBindingSnapshot) => {
      setUserRoleIds(snapshot.userRoleIds);
      setUserPermissionOverrides(snapshot.userPermissionOverrides);
      setGroupRoleIds(snapshot.groupRoleIds);
      setOrganizationRoleIds(snapshot.organizationRoleIds);
      setAuthorizationBindingsDirty(false);
      setAuthorizationPreview(null);
    },
    [],
  );

  const resetAuthorizationBindings = useCallback(() => {
    setUserRoleIds([]);
    setUserPermissionOverrides([]);
    setGroupRoleIds([]);
    setOrganizationRoleIds({});
    setAuthorizationBindingsDirty(false);
    setAuthorizationPreview(null);
    setAuthorizationLoading(false);
  }, []);

  const updateUserRoleIds = useCallback(
    (next: string[] | ((current: string[]) => string[])) => {
      setUserRoleIds(next);
      setAuthorizationBindingsDirty(true);
      setAuthorizationPreview(null);
    },
    [],
  );

  const updateGroupRoleIds = useCallback(
    (next: string[] | ((current: string[]) => string[])) => {
      setGroupRoleIds(next);
      setAuthorizationBindingsDirty(true);
      setAuthorizationPreview(null);
    },
    [],
  );

  const updateOrganizationRoleIds = useCallback(
    (
      next:
        | Record<string, string[]>
        | ((current: Record<string, string[]>) => Record<string, string[]>),
    ) => {
      setOrganizationRoleIds(next);
      setAuthorizationBindingsDirty(true);
      setAuthorizationPreview(null);
    },
    [],
  );

  const updateUserPermissionOverrides = useCallback(
    (
      next:
        | ApplicationPermissionOverride[]
        | ((current: ApplicationPermissionOverride[]) => ApplicationPermissionOverride[]),
    ) => {
      setUserPermissionOverrides(next);
      setAuthorizationBindingsDirty(true);
      setAuthorizationPreview(null);
    },
    [],
  );

  useEffect(() => {
    const request = requestContext.beginRequest("authorization:subjects", { kind: "read" });
    if (!request) return;
    setAuthorizationBindingsDirty(false);
    void Promise.all([
      applicationAuthorizationApi.listApplicationAuthorizationProfiles(
        applicationId,
        requestContext.requestOptions(request),
      ),
      applicationAuthorizationApi.listApplicationAuthorizationSubjects(
        applicationId,
        requestContext.requestOptions(request),
      ),
    ])
      .then(([profiles, subjects]) => {
        if (!requestContext.isCurrent(request)) return;
        setAuthorizationProfiles(profiles);
        setSelectedAuthorizationProfileId((current) =>
          current && profiles.some((profile) => profile.id === current)
            ? current
            : (profiles[0]?.id ?? ""),
        );
        setAuthorizationSubjects(subjects);
        setSelectedAuthorizationUserId(subjects.users[0]?.user_id ?? "");
        setSelectedAuthorizationGroupId(subjects.groups[0]?.id ?? "");
      })
      .catch(() => {
        if (!requestContext.isCurrent(request)) return;
        setAuthorizationProfiles([]);
        setSelectedAuthorizationProfileId("");
        setApplicationRoles([]);
        setApplicationPermissionCatalog([]);
        setAuthorizationSubjects(null);
      });
    return () => requestContext.finishRequest(request, false);
  }, [applicationId, requestContext, setAuthorizationBindingsDirty]);

  useEffect(() => {
    if (!selectedAuthorizationProfileId) {
      setApplicationRoles([]);
      setApplicationPermissionCatalog([]);
      return;
    }
    const request = requestContext.beginRequest(
      `authorization:profile:${selectedAuthorizationProfileId}`,
      { kind: "read" },
    );
    if (!request) return;
    void Promise.all([
      applicationAuthorizationApi.listApplicationProfileRoles(
        applicationId,
        selectedAuthorizationProfileId,
        requestContext.requestOptions(request),
      ),
      applicationAuthorizationApi.listApplicationProfilePermissionCatalog(
        applicationId,
        selectedAuthorizationProfileId,
        requestContext.requestOptions(request),
      ),
    ])
      .then(([roles, catalog]) => {
        if (!requestContext.isCurrent(request)) return;
        setApplicationRoles(roles);
        setApplicationPermissionCatalog(catalog);
      })
      .catch(() => {
        if (!requestContext.isCurrent(request)) return;
        setApplicationRoles([]);
        setApplicationPermissionCatalog([]);
        setAuthorizationFeedback(saveFailed);
      });
    return () => requestContext.finishRequest(request, false);
  }, [
    applicationId,
    requestContext,
    saveFailed,
    selectedAuthorizationProfileId,
    setAuthorizationFeedback,
  ]);

  useEffect(() => {
    const organizationRoles = authorizationSubjects?.organization_roles ?? [];
    if (!selectedAuthorizationProfileId) {
      resetAuthorizationBindings();
      return;
    }
    const request = requestContext.beginRequest(
      `authorization:bindings:${selectedAuthorizationProfileId}:${selectedAuthorizationUserId}:${selectedAuthorizationGroupId}`,
      { kind: "read" },
    );
    if (!request) return;
    setAuthorizationLoading(true);
    const scope: AuthorizationBindingScope = {
      applicationId,
      profileId: selectedAuthorizationProfileId,
      userId: selectedAuthorizationUserId || null,
      groupId: selectedAuthorizationGroupId || null,
      organizationRoles,
    };
    void reconcileAuthorizationBindings(
      scope,
      () => requestContext.isCurrent(request),
      undefined,
      { signal: request.signal },
    )
      .then((snapshot) => {
        if (!snapshot || !requestContext.isCurrent(request)) return;
        setUserRoleIds(snapshot.userRoleIds);
        setUserPermissionOverrides(snapshot.userPermissionOverrides);
        setGroupRoleIds(snapshot.groupRoleIds);
        setOrganizationRoleIds(
          Object.fromEntries(
            organizationRoles.map((role) => [
              role,
              [...(snapshot.organizationRoleIds[role] ?? [])],
            ]),
          ),
        );
        setAuthorizationPreview(null);
      })
      .catch(() => {
        if (requestContext.isCurrent(request)) setAuthorizationFeedback(saveFailed);
      })
      .finally(() => {
        if (requestContext.isCurrent(request)) setAuthorizationLoading(false);
      });
    return () => requestContext.finishRequest(request, false);
  }, [
    applicationId,
    authorizationSubjects?.organization_roles,
    requestContext,
    saveFailed,
    selectedAuthorizationGroupId,
    selectedAuthorizationProfileId,
    selectedAuthorizationUserId,
    resetAuthorizationBindings,
  ]);

  const bindings: ApplicationAuthorizationBindings = {
    userRoleIds,
    setUserRoleIds,
    groupRoleIds,
    setGroupRoleIds,
    organizationRoleIds,
    setOrganizationRoleIds,
    userPermissionOverrides,
    setUserPermissionOverrides,
    authorizationPreview,
    setAuthorizationPreview,
    authorizationLoading,
    setAuthorizationLoading,
    authorizationFeedback,
    setAuthorizationFeedback,
    authorizationBindingsDirty,
    setAuthorizationBindingsDirty,
    applyAuthorizationBindingSnapshot,
    resetAuthorizationBindings,
    updateUserRoleIds,
    updateGroupRoleIds,
    updateOrganizationRoleIds,
    updateUserPermissionOverrides,
  };

  return {
    authorizationProfiles,
    setAuthorizationProfiles,
    selectedAuthorizationProfileId,
    setSelectedAuthorizationProfileId,
    applicationRoles,
    setApplicationRoles,
    applicationPermissionCatalog,
    setApplicationPermissionCatalog,
    authorizationSubjects,
    setAuthorizationSubjects,
    selectedAuthorizationUserId,
    setSelectedAuthorizationUserId,
    selectedAuthorizationGroupId,
    setSelectedAuthorizationGroupId,
    bindings,
  };
}
