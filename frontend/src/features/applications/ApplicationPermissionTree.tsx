import { ChevronRight } from "lucide-react";
import type { ReactNode } from "react";
import { useMemo } from "react";
import type { ApplicationPermissionDefinition } from "../../lib/api/application-authorization";

type PermissionTreeNode = {
  label: string;
  children: Map<string, PermissionTreeNode>;
  definition?: ApplicationPermissionDefinition;
};

function permissionTree(definitions: ApplicationPermissionDefinition[]): PermissionTreeNode[] {
  const root: PermissionTreeNode = { label: "", children: new Map() };
  for (const definition of definitions.filter((item) => item.is_active)) {
    const segments = definition.key.split(":");
    let current = root;
    segments.forEach((segment, index) => {
      let next = current.children.get(segment);
      if (!next) {
        next = { label: segment, children: new Map() };
        current.children.set(segment, next);
      }
      if (index === segments.length - 1) next.definition = definition;
      current = next;
    });
  }
  return Array.from(root.children.values()).sort((left, right) => left.label.localeCompare(right.label));
}

export function PermissionDefinitionDetails({
  permission,
  description,
  emphasizeLabel = false
}: {
  permission: ApplicationPermissionDefinition;
  description?: string | null;
  emphasizeLabel?: boolean;
}) {
  return (
    <span>
      {emphasizeLabel ? <strong>{permission.label}</strong> : permission.label}
      <small>
        <code>{permission.key}</code>
        {description ? ` · ${description}` : ""}
      </small>
    </span>
  );
}

export function PermissionTree({
  definitions,
  renderLeaf
}: {
  definitions: ApplicationPermissionDefinition[];
  renderLeaf: (definition: ApplicationPermissionDefinition) => ReactNode;
}) {
  function renderNode(node: PermissionTreeNode, depth: number): ReactNode {
    const children = Array.from(node.children.values()).sort((left, right) => left.label.localeCompare(right.label));
    return (
      <div className="permission-tree-node" key={`${node.definition?.key ?? node.label}-${depth}`}>
        {node.definition && renderLeaf(node.definition)}
        {!node.definition && <div className="permission-tree-branch"><ChevronRight size={13} /><strong>{node.label}</strong></div>}
        {children.length > 0 && <div className="permission-tree-children">{children.map((child) => renderNode(child, depth + 1))}</div>}
      </div>
    );
  }

  const nodes = useMemo(() => permissionTree(definitions), [definitions]);
  return <div className="permission-tree">{nodes.length > 0 ? nodes.map((node) => renderNode(node, 0)) : <p className="muted">{"—"}</p>}</div>;
}
