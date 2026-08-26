import { pathSegment } from "./transport";

export function appendPathSegment(path: string, segment: string): string {
  return `${path}/${pathSegment(segment)}`;
}
