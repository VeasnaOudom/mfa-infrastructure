import { useCallback, useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import {
  AccountEnvironment,
  Page,
  useAccountAlerts,
  useEnvironment
} from "@keycloak/keycloak-account-ui";
import { type AccountActivity, fetchAccountActivities, } from "../api/accountActivities";
import { EMPTY_EVENTS_FILTER, type EventsFilter, EventsTable, } from "./EventsTable";

const PAGE_SIZE = 10;

export const AccountActivities = () => {
  const {t} = useTranslation();
  const context = useEnvironment<AccountEnvironment>();
  const {addError} = useAccountAlerts();

  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(PAGE_SIZE);
  const [filter, setFilter] = useState<EventsFilter>(EMPTY_EVENTS_FILTER);
  const [activities, setActivities] = useState<AccountActivity[]>();
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const controller = new AbortController();
    setLoading(true);

    fetchAccountActivities(context, {
      first: (page - 1) * pageSize,
      max: pageSize,
      filter: {
        type: filter.type,
        dateFrom: filter.dateFrom || undefined,
        dateTo: filter.dateTo || undefined,
        ipAddress: filter.ipAddress || undefined,
      },
      signal: controller.signal,
    })
      .then((data) => {
        setActivities(data.events);
      })
      .catch((e) => {
        if (e instanceof DOMException && e.name === "AbortError") {
          return;
        }
        setActivities([]);
        addError(t("accountActivitiesLoadError"), e);
      })
      .finally(() => {
        if (!controller.signal.aborted) {
          setLoading(false);
        }
      });

    return () => controller.abort();
  }, [context, page, pageSize, filter, t, addError]);

  const onPerPageChange = useCallback((max: number) => {
    setPageSize(max);
    setPage(1);
  }, []);

  return (
    <Page
      title={t("accountActivities")}
      description={t("accountActivitiesDescription")}
    >
      <EventsTable
        activities={activities ?? []}
        loading={loading}
        count={activities?.length ?? 0}
        first={(page - 1) * pageSize}
        max={pageSize}
        onPage={setPage}
        activeFilter={filter}
        onFilter={setFilter}
        onPerPage={onPerPageChange}
      />
    </Page>
  );
};
