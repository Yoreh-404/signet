import type { TranslationKey } from "../../i18n";

type Translate = (key: TranslationKey) => string;

export type UserDirectoryPaginationProps = {
  page: number;
  start: number;
  end: number;
  loading: boolean;
  hasNextPage: boolean;
  translate: Translate;
  onPrevious: () => void;
  onNext: () => void;
};

export function UserDirectoryPagination({
  page,
  start,
  end,
  loading,
  hasNextPage,
  translate,
  onPrevious,
  onNext
}: UserDirectoryPaginationProps) {
  return (
    <div className="user-pagination" aria-label={translate("users")}>
      <span>
        {translate("cursorPageSummary")
          .replace("{page}", String(page))
          .replace("{from}", String(start))
          .replace("{to}", String(end))}
      </span>
      <div className="actions">
        <button
          type="button"
          className="text-button"
          aria-label={translate("previousPage")}
          onClick={onPrevious}
          disabled={loading || page <= 1}
        >{translate("previousPage")}</button>
        <button
          type="button"
          className="text-button"
          aria-label={translate("nextPage")}
          onClick={onNext}
          disabled={loading || !hasNextPage}
        >{translate("nextPage")}</button>
      </div>
    </div>
  );
}
