import { useEffect, type Dispatch, type RefObject, type SetStateAction } from "react";

type UseMobileSidebarFocusTrapOptions = {
  open: boolean;
  sidebarRef: RefObject<HTMLElement>;
  mobileMenuButtonRef: RefObject<HTMLButtonElement>;
  setOpen: Dispatch<SetStateAction<boolean>>;
};

export function useMobileSidebarFocusTrap({
  open,
  sidebarRef,
  mobileMenuButtonRef,
  setOpen
}: UseMobileSidebarFocusTrapOptions) {
  useEffect(() => {
    if (!open || !sidebarRef.current) return;
    const sidebar = sidebarRef.current;
    const previousOverflow = document.body.style.overflow;
    const focusableElements = () => [...sidebar.querySelectorAll<HTMLElement>(
      "a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex='-1'])"
    )].filter((element) => element.getClientRects().length > 0);
    const focusFrame = window.requestAnimationFrame(() => focusableElements()[0]?.focus());
    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        event.preventDefault();
        setOpen(false);
        return;
      }
      if (event.key !== "Tab") return;
      const focusable = focusableElements();
      if (focusable.length === 0) {
        event.preventDefault();
        return;
      }
      const first = focusable[0];
      const last = focusable[focusable.length - 1];
      if (event.shiftKey && document.activeElement === first) {
        event.preventDefault();
        last?.focus();
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault();
        first.focus();
      }
    };
    document.body.style.overflow = "hidden";
    document.addEventListener("keydown", handleKeyDown);
    return () => {
      window.cancelAnimationFrame(focusFrame);
      document.removeEventListener("keydown", handleKeyDown);
      document.body.style.overflow = previousOverflow;
      window.requestAnimationFrame(() => mobileMenuButtonRef.current?.focus());
    };
  }, [mobileMenuButtonRef, open, setOpen, sidebarRef]);
}
