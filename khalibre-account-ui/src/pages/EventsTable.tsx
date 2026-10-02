import {
  ActionGroup,
  Button,
  Chip,
  ChipGroup,
  DatePicker,
  EmptyState,
  EmptyStateBody,
  EmptyStateHeader,
  EmptyStateVariant,
  Form,
  FormGroup,
  Label,
  MenuToggle,
  Pagination,
  PaginationToggleTemplateProps,
  SelectOption,
  Spinner,
  TextInput,
} from "@patternfly/react-core";
import { KeycloakSelect } from "@keycloak/keycloak-ui-shared";
import { useEffect, useRef, useState } from "react";
import { Table, Tbody, Td, Th, Thead, Tr } from "@patternfly/react-table";
import { useTranslation } from "react-i18next";
import {
  type AccountActivity,
  ALL_EVENT_TYPES,
  eventTypeFallback,
  eventTypeKey,
} from "../api/accountActivities";
import { formatDateTime } from "../utils/formatDate";
import { isErrorActivity } from "../utils/events";
import styles from "./EventsTable.module.css";

type EventsTableProps = {
  activities: AccountActivity[];
  loading: boolean;
  count: number;
  first: number;
  max: number;
  onPage: (page: number) => void;
  activeFilter: EventsFilter;
  onFilter: (filter: EventsFilter) => void;
  onPerPage: (perPage: number) => void;
};

/** Detail keys rendered as a "Key: value" list. */
const DETAIL_LABELS: Record<string, string> = {
  auth_method: "accountActivitiesDetailAuthMethod",
  identity_provider: "accountActivitiesDetailIdentityProvider",
  identity_provider_auth_method: "accountActivitiesDetailIdpAuthMethod",
  auth_method_details: "accountActivitiesDetailAuthMethodDetails",
};

export type EventsFilter = {
  type: string[];
  dateFrom: string;
  dateTo: string;
  ipAddress: string;
};

export const EMPTY_EVENTS_FILTER: EventsFilter = {
  type: [],
  dateFrom: "",
  dateTo: "",
  ipAddress: "",
};

export const EventsTable = ({
                              activities,
                              loading,
                              first,
                              max,
                              count,
                              onPage,
                              activeFilter,
                              onFilter,
                              onPerPage,
                            }: EventsTableProps) => {
  const {t} = useTranslation();

  const toEventTypeValue = (value: string | number | object) => {
    if (typeof value === "string" || typeof value === "number") {
      return String(value);
    }

    if (
      typeof value === "object" &&
      value !== null &&
      "value" in value &&
      typeof (value as { value?: unknown }).value !== "undefined"
    ) {
      return String((value as { value: unknown }).value);
    }

    return String(value);
  };

  const [draftFilter, setDraftFilter] = useState<EventsFilter>(activeFilter);
  const dropdownRef = useRef<HTMLDivElement>(null);

  const [searchOpen, setSearchOpen] = useState(false);
  const [typeSelectOpen, setTypeSelectOpen] = useState(false);

  const filterLabels: Record<keyof EventsFilter, string> = {
    type: t("accountActivitiesEventType"),
    dateFrom: t("accountActivitiesDateFrom"),
    dateTo: t("accountActivitiesDateTo"),
    ipAddress: t("accountActivitiesIpAddress"),
  };

  const hasActiveFilters =
    activeFilter.type.length > 0 ||
    activeFilter.dateFrom !== "" ||
    activeFilter.dateTo !== "" ||
    activeFilter.ipAddress !== "";

  const isDraftDirty =
    draftFilter.type.length > 0 ||
    draftFilter.dateFrom !== "" ||
    draftFilter.dateTo !== "" ||
    draftFilter.ipAddress !== "";

  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (
        dropdownRef.current &&
        !dropdownRef.current.contains(event.target as Node)
      ) {
        setSearchOpen(false);
      }
    };

    document.addEventListener("mousedown", handleClickOutside);
    return () => document.removeEventListener("mousedown", handleClickOutside);
  }, [setSearchOpen]);

  useEffect(() => {
    const handleVisibilityChange = () => {
      if (document.visibilityState === "hidden") {
        setSearchOpen(false);
      }
    };

    document.addEventListener("visibilitychange", handleVisibilityChange);
    return () =>
      document.removeEventListener("visibilitychange", handleVisibilityChange);
  }, [setSearchOpen]);

  const eventTypeLabel = (type: string) =>
    t(eventTypeKey(type), {defaultValue: eventTypeFallback(type)});

  const commitFilters = (filter: EventsFilter) => {
    onFilter(filter);
    onPage(1);
  };

  const onSubmit = () => {
    setSearchOpen(false);
    commitFilters(draftFilter);
  };

  const resetSearch = () => {
    setDraftFilter(EMPTY_EVENTS_FILTER);
    commitFilters(EMPTY_EVENTS_FILTER);
  };

  const removeFilter = (key: keyof EventsFilter) => {
    const next = {...activeFilter, [key]: EMPTY_EVENTS_FILTER[key]};
    setDraftFilter((prev) => ({...prev, [key]: EMPTY_EVENTS_FILTER[key]}));
    commitFilters(next);
  };

  const removeType = (value: string) => {
    const next = {
      ...activeFilter,
      type: activeFilter.type.filter((item) => item !== value),
    };
    setDraftFilter((prev) => ({
      ...prev,
      type: prev.type.filter((item) => item !== value),
    }));
    commitFilters(next);
  };

  const showNoData = activities.length === 0 && !hasActiveFilters;
  const showNoSearchResults = activities.length === 0 && !showNoData;

  if (showNoData) {
    return (
      <EmptyState>
        <EmptyStateHeader titleText={t("accountActivitiesEmptyTitle")}/>
        <EmptyStateBody>{t("accountActivitiesEmpty")}</EmptyStateBody>
      </EmptyState>
    );
  }

  // This follows Keycloak's table pattern for unknown totals:
  // when a page is full, expose one extra item to keep "next page" available.
  const page = Math.floor(first / max) + 1;
  const itemCount = first + (count < max ? count : count + 1);

  return (
    <>
      <div className={styles.activityCard}>
        <div className={styles.toolbar}>
          <div className={styles.searchFilter}>
            <div className={styles.filterPanelWrap} ref={dropdownRef}>
              <MenuToggle
                onClick={() => setSearchOpen(!searchOpen)}
                isExpanded={searchOpen}
                className={styles.menuToggle}
              >
                {t("accountActivitiesSearchEvents")}
              </MenuToggle>
              {searchOpen && (
                <div className={styles.filterPanel}>
                  <Form
                    isHorizontal
                    onSubmit={(event) => {
                      event.preventDefault();
                      onSubmit();
                    }}
                  >
                    <FormGroup
                      label={t("accountActivitiesEventType")}
                      fieldId="kc-eventType"
                    >
                      <KeycloakSelect
                        variant={"typeaheadMulti" as never}
                        maxHeight={300}
                        typeAheadAriaLabel={t("accountActivitiesEventType")}
                        chipGroupProps={{
                          numChips: 1,
                          expandedText: t("accountActivitiesHide"),
                          collapsedText: t("accountActivitiesShowRemaining"),
                        }}
                        onToggle={setTypeSelectOpen}
                        isOpen={typeSelectOpen}
                        selections={draftFilter.type}
                        onSelect={(value) => {
                          const option = toEventTypeValue(value);
                          if (!option) {
                            return;
                          }
                          setDraftFilter((prev) => ({
                            ...prev,
                            type: prev.type.includes(option)
                              ? prev.type.filter((item) => item !== option)
                              : [...prev.type, option],
                          }));
                        }}
                        onClear={() =>
                          setDraftFilter((prev) => ({...prev, type: []}))
                        }
                        chipGroupComponent={
                          <ChipGroup>
                            {draftFilter.type.map((chip) => (
                              <Chip
                                key={chip}
                                onClick={(event) => {
                                  event.stopPropagation();
                                  setDraftFilter((prev) => ({
                                    ...prev,
                                    type: prev.type.filter((item) => item !== chip),
                                  }));
                                }}
                              >
                                {eventTypeLabel(chip)}
                              </Chip>
                            ))}
                          </ChipGroup>
                        }
                      >
                        {ALL_EVENT_TYPES.map((option) => (
                          <SelectOption
                            key={option}
                            value={option}
                            selected={draftFilter.type.includes(option)}
                          >
                            {eventTypeLabel(option)}
                          </SelectOption>
                        ))}
                      </KeycloakSelect>
                    </FormGroup>

                    <FormGroup
                      label={t("accountActivitiesDateFrom")}
                      fieldId="kc-dateFrom"
                    >
                      <DatePicker
                        className="pf-v5-u-w-100"
                        value={draftFilter.dateFrom}
                        onChange={(_event, value) =>
                          setDraftFilter((prev) => ({...prev, dateFrom: value}))
                        }
                        inputProps={{id: "kc-dateFrom"}}
                      />
                    </FormGroup>

                    <FormGroup
                      label={t("accountActivitiesDateTo")}
                      fieldId="kc-dateTo"
                    >
                      <DatePicker
                        className="pf-v5-u-w-100"
                        value={draftFilter.dateTo}
                        onChange={(_event, value) =>
                          setDraftFilter((prev) => ({...prev, dateTo: value}))
                        }
                        inputProps={{id: "kc-dateTo"}}
                      />
                    </FormGroup>

                    <FormGroup
                      label={t("accountActivitiesIpAddress")}
                      fieldId="kc-ipAddress"
                    >
                      <TextInput
                        id="kc-ipAddress"
                        value={draftFilter.ipAddress}
                        onChange={(_event, value) =>
                          setDraftFilter((prev) => ({...prev, ipAddress: value}))
                        }
                      />
                    </FormGroup>

                    <ActionGroup className="pf-v5-u-mt-0">
                      <Button
                        variant="primary"
                        type="submit"
                        isDisabled={!isDraftDirty}
                      >
                        {t("accountActivitiesSearchBtn")}
                      </Button>
                      <Button
                        variant="secondary"
                        onClick={resetSearch}
                        isDisabled={!isDraftDirty && !hasActiveFilters}
                      >
                        {t("accountActivitiesResetBtn")}
                      </Button>
                    </ActionGroup>
                  </Form>
                </div>
              )}
            </div>
          </div>
          <p
            className={`pf-v5-u-font-weight-normal pf-v5-u-color-200 pf-v5-u-align-self-end ${styles.edcInfo}`}>
            {t("accountActivitiesEdcKeeps90days")}
          </p>
        </div>

        {hasActiveFilters && (
          <div className={styles.chips}>
            {activeFilter.type.length > 0 && (
              <ChipGroup
                categoryName={filterLabels.type}
                isClosable
                onClick={() => removeFilter("type")}
              >
                {activeFilter.type.map((entry) => (
                  <Chip key={entry} onClick={() => removeType(entry)}>
                    {eventTypeLabel(entry)}
                  </Chip>
                ))}
              </ChipGroup>
            )}
            {activeFilter.dateFrom !== "" && (
              <ChipGroup
                categoryName={filterLabels.dateFrom}
                isClosable
                onClick={() => removeFilter("dateFrom")}
              >
                <Chip isReadOnly>{activeFilter.dateFrom}</Chip>
              </ChipGroup>
            )}
            {activeFilter.dateTo !== "" && (
              <ChipGroup
                categoryName={filterLabels.dateTo}
                isClosable
                onClick={() => removeFilter("dateTo")}
              >
                <Chip isReadOnly>{activeFilter.dateTo}</Chip>
              </ChipGroup>
            )}
            {activeFilter.ipAddress !== "" && (
              <ChipGroup
                categoryName={filterLabels.ipAddress}
                isClosable
                onClick={() => removeFilter("ipAddress")}
              >
                <Chip isReadOnly>{activeFilter.ipAddress}</Chip>
              </ChipGroup>
            )}
          </div>
        )}

        <div className={styles.tableWrap}>
          <Table aria-label={t("accountActivities")} variant="compact" borders
                 className={styles.activityTable}>
            <Thead>
              <Tr>
                <Th style={{verticalAlign: 'middle'}}>{t("accountActivitiesDate")}</Th>
                <Th style={{verticalAlign: 'middle'}}>{t("accountActivitiesEvent")}</Th>
                <Th style={{verticalAlign: 'middle'}}>{t("accountActivitiesClient")}</Th>
                <Th style={{verticalAlign: 'middle'}}>{t("accountActivitiesIpAddress")}</Th>
                <Th style={{verticalAlign: 'middle'}}>{t("accountActivitiesDetails")}</Th>
                <Th style={{verticalAlign: 'middle'}}>{t("accountActivitiesResult")}</Th>
              </Tr>
            </Thead>

            <Tbody>
              {loading ? (
                <Tr>
                  <Td colSpan={6}
                      style={{textAlign: 'center', verticalAlign: 'middle'}}>
                    <div className={styles.tableLoading}>
                      <Spinner className={styles.tableSpinner}/>
                    </div>
                  </Td>
                </Tr>
              ) : (
                activities.map((activity, index) => {
                  const typeKey = eventTypeKey(activity.type);
                  const details = Object.entries(activity.details ?? {}).filter(
                    ([key]) => key in DETAIL_LABELS,
                  );

                  return (
                    <Tr key={`${activity.time}-${index}`}>
                      <Td style={{verticalAlign: 'middle'}}
                          dataLabel={t("accountActivitiesDate")}>
                        {formatDateTime(activity.time)}
                      </Td>
                      <Td style={{verticalAlign: 'middle'}}
                          dataLabel={t("accountActivitiesEvent")}>
                        <Label
                          color={isErrorActivity(activity) ? "red" : "grey"}
                          isCompact
                        >
                          {t(typeKey, {
                            defaultValue: eventTypeFallback(activity.type),
                          })}
                        </Label>
                        {activity.error ? <div>{activity.error}</div> : null}
                      </Td>
                      <Td style={{verticalAlign: 'middle'}}
                          dataLabel={t("accountActivitiesClient")}>
                        {activity.clientId ?? "-"}
                      </Td>
                      <Td style={{verticalAlign: 'middle'}}
                          dataLabel={t("accountActivitiesIpAddress")}>
                        {activity.ipAddress ?? "-"}
                      </Td>
                      <Td style={{verticalAlign: 'middle'}}
                          dataLabel={t("accountActivitiesDetails")}>
                        {details.length === 0 ? (
                          "-"
                        ) : (
                          <dl>
                            {details.map(([key, value]) => (
                              <div key={key}>
                                <dt>{t(DETAIL_LABELS[key])}</dt>
                                <dd>{value}</dd>
                              </div>
                            ))}
                          </dl>
                        )}
                      </Td>
                      <Td style={{verticalAlign: 'middle'}}
                          dataLabel={t("accountActivitiesResult")}>
                        <Label color={activity.error == null ? "green" : "red"}
                               className="pf-v5-u-font-weight-bold">
                          {activity.error == null ? t("accountActivitiesSuccess") : t("accountActivitiesBlocked")}
                        </Label>
                      </Td>
                    </Tr>
                  );
                })
              )}
            </Tbody>
          </Table>

          {!loading && showNoSearchResults && (
            <EmptyState variant={EmptyStateVariant.lg} className={styles.emptyState}>
              <EmptyStateHeader titleText={t("accountActivitiesNoSearchResultsTitle")}/>
              <EmptyStateBody>{t("accountActivitiesNoSearchResults")}</EmptyStateBody>
            </EmptyState>
          )}
        </div>

        <div className={styles.footer}>
          <Pagination
            itemCount={itemCount}
            page={page}
            perPage={max}
            widgetId="account-activities-pagination"
            isCompact
            toggleTemplate={({
               firstIndex,
               lastIndex,
             }: PaginationToggleTemplateProps) => (
              <b>
                {firstIndex} - {lastIndex}
              </b>
            )}
            onNextClick={(_, nextPage) => onPage(nextPage)}
            onPreviousClick={(_, previousPage) => onPage(previousPage)}
            onSetPage={(_, nextPage) => onPage(nextPage)}
            onPerPageSelect={(_, perPage) => onPerPage(perPage)}
          />
        </div>
      </div>

      <div className={styles.helpBanner}>
        <p>{t("accountActivity.see-something-you-did-not-recognise")}</p>
      </div>
    </>
  );
};
