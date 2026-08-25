import { useState } from "react";
import { emptyGroupForm, emptyRoleForm } from "../../lib/form-defaults";
import type { AccessGroup, Role, UserAccess } from "../../types";

/** Owns roles, groups, organization role assignments, and access inspection. */
export function useRoleController() {
  const [roleForm, setRoleForm] = useState(emptyRoleForm);
  const [roleFormBaseline, setRoleFormBaseline] = useState<typeof emptyRoleForm | null>(null);
  const [groupForm, setGroupForm] = useState(emptyGroupForm);
  const [groupFormBaseline, setGroupFormBaseline] = useState<typeof emptyGroupForm | null>(null);
  const [selectedAccessUserId, setSelectedAccessUserId] = useState("");
  const [userAccess, setUserAccess] = useState<UserAccess | null>(null);
  const [roleSnapshot, setRoleSnapshot] = useState<Role[]>([]);
  const [groupSnapshot, setGroupSnapshot] = useState<AccessGroup[]>([]);

  return {
    roleForm,
    setRoleForm,
    roleFormBaseline,
    setRoleFormBaseline,
    groupForm,
    setGroupForm,
    groupFormBaseline,
    setGroupFormBaseline,
    selectedAccessUserId,
    setSelectedAccessUserId,
    userAccess,
    setUserAccess,
    roleSnapshot,
    setRoleSnapshot,
    groupSnapshot,
    setGroupSnapshot
  };
}

export type RoleController = ReturnType<typeof useRoleController>;

