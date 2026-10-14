import { type FormEvent, useCallback, useEffect, useMemo, useState } from "react";
import { useTranslation } from "react-i18next";
import {
  Alert,
  AlertVariant,
  Bullseye,
  Button,
  ButtonVariant,
  Card,
  CardBody,
  CardHeader,
  CardTitle,
  Dropdown,
  DropdownItem,
  DropdownList,
  Form,
  FormGroup,
  FormHelperText,
  Label,
  MenuToggle,
  Modal,
  PageSection,
  SearchInput,
  Spinner,
  Switch,
  Tabs,
  Tab,
  TabTitleText,
  Text,
  TextContent,
  TextVariants,
  Toolbar,
  ToolbarContent,
  ToolbarItem,
} from "@patternfly/react-core";
import { EllipsisVIcon } from "@patternfly/react-icons";
import { Table, Tbody, Td, Th, Thead, Tr } from "@patternfly/react-table";
import {
  getInjectedEnvironment,
  useAlerts,
  useEnvironment,
} from "@keycloak/keycloak-ui-shared";
import { useParams } from "react-router-dom";

import {
  AdminApi,
  ApplicationPolicy,
  CHANNEL_NAMES,
  ChannelName,
  clearClientPolicy,
  detailOf,
  fetchChannels,
  messageOf,
  setChannels,
} from "./api";

type ChannelMap = Record<ChannelName, boolean>;

/** One map per switch group, because "on" and "required" are two different decisions. */
type Policy = { enabled: ChannelMap; required: ChannelMap };

const ALL_OFF: ChannelMap = {
  email: false,
  telegram: false,
  totp: false,
};

function toPolicy(rows: { channel: ChannelName; enabled: boolean; required: boolean }[]): Policy {
  const enabled: ChannelMap = { ...ALL_OFF };
  const required: ChannelMap = { ...ALL_OFF };
  for (const row of rows) {
    enabled[row.channel] = row.enabled;
    // The server already refuses to require a channel it has switched off, so a stored pair that
    // disagrees cannot arrive - but mirroring that here keeps the required switch inert rather than
    // showing a requirement that is not in force.
    required[row.channel] = row.enabled && row.required;
  }
  return { enabled, required };
}

function samePolicy(a: Policy, b: Policy): boolean {
  return CHANNEL_NAMES.every(
    (name) => a.enabled[name] === b.enabled[name] && a.required[name] === b.required[name],
  );
}

function formatDate(iso: string | null): string {
  if (!iso) return "—";
  try {
    const d = new Date(iso);
    if (isNaN(d.getTime())) return iso;
    return d.toLocaleDateString("en-GB", { day: "numeric", month: "short", year: "numeric" });
  } catch {
    return iso;
  }
}

/**
 * The save row, kept out of the page body so the form and its button cannot drift apart.
 *
 * Revert is the point of the pair: this control writes straight to the realm, so an admin who has
 * flicked four switches and changed their mind needs one click back to the stored policy rather
 * than four clicks back.
 */
function SaveRow({
  saving,
  disabled,
  onRevert,
}: {
  saving: boolean;
  disabled: boolean;
  onRevert: () => void;
}) {
  const { t } = useTranslation();
  return (
    <div className="pf-v5-u-mt-lg">
      <Button
        variant={ButtonVariant.primary}
        type="submit"
        isDisabled={disabled}
        isLoading={saving}
        data-testid="edc-mfa-save"
      >
        {t("save")}
      </Button>
      <Button
        variant={ButtonVariant.link}
        className="pf-v5-u-ml-md"
        isDisabled={disabled}
        onClick={onRevert}
      >
        {t("revert")}
      </Button>
    </div>
  );
}

function AppActionDropdown({
  app,
  onEdit,
  onReset,
}: {
  app: ApplicationPolicy;
  onEdit: () => void;
  onReset: () => void;
}) {
  const { t } = useTranslation();
  const [isOpen, setIsOpen] = useState(false);

  return (
    <Dropdown
      isOpen={isOpen}
      onOpenChange={(open) => setIsOpen(open)}
      toggle={(ref) => (
        <MenuToggle
          ref={ref}
          isExpanded={isOpen}
          variant="plain"
          onClick={() => setIsOpen(!isOpen)}
          aria-label="Actions"
        >
          <EllipsisVIcon />
        </MenuToggle>
      )}
    >
      <DropdownList>
        <DropdownItem
          key="edit"
          onClick={() => {
            setIsOpen(false);
            onEdit();
          }}
        >
          {t("edcMfaConfigureChannels")}
        </DropdownItem>
        {!app.inherited && (
          <DropdownItem
            key="reset"
            onClick={() => {
              setIsOpen(false);
              onReset();
            }}
          >
            {t("edcMfaResetToDefault")}
          </DropdownItem>
        )}
      </DropdownList>
    </Dropdown>
  );
}

function AppEditModal({
  app,
  isOpen,
  onClose,
  onSave,
  saving,
}: {
  app: ApplicationPolicy | null;
  isOpen: boolean;
  onClose: () => void;
  onSave: (appId: string, inherit: boolean, policy: Policy) => Promise<void>;
  saving: boolean;
}) {
  const { t } = useTranslation();
  const [inherit, setInherit] = useState(true);
  const [draft, setDraft] = useState<Policy>({ enabled: ALL_OFF, required: ALL_OFF });

  useEffect(() => {
    if (app) {
      setInherit(app.inherited);
      setDraft(toPolicy(app.channels));
    }
  }, [app]);

  if (!app) return null;

  const noneEnabled = !inherit && CHANNEL_NAMES.every((name) => !draft.enabled[name]);
  const draftRequired = CHANNEL_NAMES.filter((name) => draft.required[name]);

  return (
    <Modal
      variant="medium"
      title={t("edcMfaEditAppTitle", { name: app.name || app.clientId })}
      description={t("edcMfaEditAppIntro")}
      isOpen={isOpen}
      onClose={onClose}
      actions={[
        <Button
          key="save"
          variant={ButtonVariant.primary}
          isDisabled={noneEnabled || saving}
          isLoading={saving}
          onClick={() => onSave(app.clientId, inherit, draft)}
        >
          {t("save")}
        </Button>,
        <Button key="cancel" variant={ButtonVariant.link} onClick={onClose} isDisabled={saving}>
          {t("cancel")}
        </Button>,
      ]}
    >
      <Form isHorizontal className="pf-v5-u-mt-md">
        <FormGroup fieldId="app-inherit" label={t("edcMfaInheritToggle")}>
          <Switch
            id="app-inherit"
            label={t("edcMfaInherit")}
            isChecked={inherit}
            onChange={(_event, checked) => setInherit(checked)}
          />
          <FormHelperText>
            <Text component={TextVariants.small}>{t("edcMfaInheritedHint")}</Text>
          </FormHelperText>
        </FormGroup>

        {!inherit && (
          <FormGroup fieldId="app-custom-channels" label={t("edcMfaChannelsCard")}>
            {CHANNEL_NAMES.map((name) => (
              <div key={name} className="pf-v5-u-mb-md">
                <Switch
                  id={`app-channel-${name}`}
                  label={t(`edcMfaChannel_${name}`)}
                  isChecked={draft.enabled[name]}
                  onChange={(_event, checked) =>
                    setDraft((current) => {
                      const enabled = { ...current.enabled, [name]: checked };
                      const required = checked
                        ? current.required
                        : { ...current.required, [name]: false };
                      return { enabled, required };
                    })
                  }
                />
                <Switch
                  id={`app-required-${name}`}
                  className="pf-v5-u-ml-md"
                  label={t("edcMfaRequired")}
                  isDisabled={!draft.enabled[name]}
                  isChecked={draft.required[name]}
                  onChange={(_event, checked) =>
                    setDraft((current) => ({
                      ...current,
                      required: { ...current.required, [name]: checked },
                    }))
                  }
                />
                <FormHelperText>
                  <Text component={TextVariants.small}>
                    {t(`edcMfaRequired_${name}_hint`)}
                  </Text>
                </FormHelperText>
              </div>
            ))}
            {/* Spelled out where it is being decided. "Required" on three rows reads as "any one of
                them" to almost everyone, and the server means all of them - the wizard walks a user
                through them one at a time. */}
            {draftRequired.length > 0 && (
              <Alert
                isInline
                variant={AlertVariant.info}
                title={t("edcMfaRequiredExplainerModal", {
                  channels: draftRequired.map((name) => t(`edcMfaChannel_${name}`)).join(", "),
                })}
                className="pf-v5-u-mt-sm"
              />
            )}
            {noneEnabled && (
              <Alert
                isInline
                variant={AlertVariant.warning}
                title={t("edcMfaNoneEnabled")}
                className="pf-v5-u-mt-sm"
              />
            )}
          </FormGroup>
        )}
      </Form>
    </Modal>
  );
}

export default function EdcMfaChannels() {
  const { t } = useTranslation();
  const { realm } = useParams<{ realm: string }>();
  const { keycloak } = useEnvironment();
  const { addAlert } = useAlerts();

  const [activeTab, setActiveTab] = useState<number>(1); // Default to Applications tab as in design
  const [stored, setStored] = useState<Policy | null>(null);
  const [draft, setDraft] = useState<Policy>({ enabled: ALL_OFF, required: ALL_OFF });
  const [applications, setApplications] = useState<ApplicationPolicy[]>([]);
  const [telegramConfigured, setTelegramConfigured] = useState(true);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState("");
  const [saving, setSaving] = useState(false);

  // Search filter for applications
  const [search, setSearch] = useState("");

  // Modal editing
  const [editingApp, setEditingApp] = useState<ApplicationPolicy | null>(null);

  const environment = useMemo(
    () => getInjectedEnvironment<{ serverBaseUrl: string; realm: string }>(),
    [],
  );

  const getToken = useCallback(async () => {
    await keycloak.updateToken(5);
    return keycloak.token ?? "";
  }, [keycloak]);

  const api = useMemo<AdminApi>(
    () => ({
      serverBaseUrl: environment.serverBaseUrl,
      realm: realm ?? environment.realm,
      getToken,
    }),
    [environment, realm, getToken],
  );

  const load = useCallback(async () => {
    setLoading(true);
    setLoadError("");
    try {
      const result = await fetchChannels(api);
      const next = toPolicy(result.default.channels);
      setTelegramConfigured(result.telegramConfigured);
      setStored(next);
      setDraft(next);
      setApplications(result.applications);
    } catch (error) {
      setLoadError(messageOf(error));
    } finally {
      setLoading(false);
    }
  }, [api]);

  useEffect(() => {
    void load();
  }, [load]);

  const dirty = stored !== null && !samePolicy(stored, draft);
  const noneEnabled = CHANNEL_NAMES.every((name) => !draft.enabled[name]);
  const requiredCount = CHANNEL_NAMES.filter((name) => draft.required[name]).length;

  const saveRealmDefault = async (event: FormEvent) => {
    event.preventDefault();
    if (noneEnabled) {
      return;
    }
    setSaving(true);
    try {
      const result = await setChannels(api, draft.enabled, draft.required);
      const next = toPolicy(result.default.channels);
      setStored(next);
      setDraft(next);
      setApplications(result.applications);
      setTelegramConfigured(result.telegramConfigured);
      addAlert(t("edcMfaSaved"), AlertVariant.success);
    } catch (error) {
      addAlert(
        messageOf(error) || t("edcMfaSaveFailed"),
        AlertVariant.danger,
        detailOf(error),
      );
      await load();
    } finally {
      setSaving(false);
    }
  };

  const handleSaveAppModal = async (clientId: string, inherit: boolean, policy: Policy) => {
    setSaving(true);
    try {
      if (inherit) {
        const result = await clearClientPolicy(api, clientId);
        setApplications(result.applications);
        addAlert(t("edcMfaAppCleared"), AlertVariant.success);
      } else {
        const result = await setChannels(api, policy.enabled, policy.required, clientId);
        setApplications(result.applications);
        addAlert(t("edcMfaAppSaved"), AlertVariant.success);
      }
      setEditingApp(null);
    } catch (error) {
      addAlert(messageOf(error) || t("edcMfaSaveFailed"), AlertVariant.danger, detailOf(error));
    } finally {
      setSaving(false);
    }
  };

  const handleResetAppToDefault = async (clientId: string) => {
    setSaving(true);
    try {
      const result = await clearClientPolicy(api, clientId);
      setApplications(result.applications);
      addAlert(t("edcMfaAppCleared"), AlertVariant.success);
    } catch (error) {
      addAlert(messageOf(error) || t("edcMfaSaveFailed"), AlertVariant.danger, detailOf(error));
    } finally {
      setSaving(false);
    }
  };

  const filteredApps = useMemo(() => {
    if (!search.trim()) return applications;
    const lower = search.toLowerCase();
    return applications.filter(
      (app) => app.name.toLowerCase().includes(lower) || app.clientId.toLowerCase().includes(lower),
    );
  }, [applications, search]);

  return (
    <>
      <PageSection>
        <TextContent>
          <Text component={TextVariants.h1}>{t("edcMfaChannels")}</Text>
          <Text component={TextVariants.p}>{t("edcMfaSubtitle")}</Text>
        </TextContent>
      </PageSection>

      <PageSection>
        <Tabs
          activeKey={activeTab}
          onSelect={(_event, tabIndex) => setActiveTab(Number(tabIndex))}
          className="pf-v5-u-mb-lg"
        >
          <Tab eventKey={0} title={<TabTitleText>{t("edcMfaTabSettings")}</TabTitleText>} />
          <Tab eventKey={1} title={<TabTitleText>{t("edcMfaTabApplications")}</TabTitleText>} />
        </Tabs>

        {loading && (
          <Bullseye>
            <Spinner size="lg" />
          </Bullseye>
        )}

        {!loading && loadError && (
          <Alert
            isInline
            variant={AlertVariant.danger}
            title={t("edcMfaLoadFailed", { error: loadError })}
            className="pf-v5-u-mb-md"
          />
        )}

        {!loading && !loadError && activeTab === 0 && (
          <Card>
            <CardHeader>
              <CardTitle>{t("edcMfaChannelsCard")}</CardTitle>
            </CardHeader>
            <CardBody>
              <TextContent>
                <Text component={TextVariants.p}>{t("edcMfaNonDestructive")}</Text>
              </TextContent>

              <Form isHorizontal onSubmit={saveRealmDefault} className="pf-v5-u-mt-md">
                <FormGroup
                  role="group"
                  fieldId="edc-mfa-channels"
                  label={t("edcMfaChannelsCard")}
                >
                  {CHANNEL_NAMES.map((name) => (
                    <div key={name} className="pf-v5-u-mb-lg">
                      <Switch
                        id={`edc-mfa-channel-${name}`}
                        name={`edc-mfa-channel-${name}`}
                        label={t(`edcMfaChannel_${name}`)}
                        isChecked={draft.enabled[name]}
                        onChange={(_event, checked) =>
                          setDraft((current) => {
                            const enabled = { ...current.enabled, [name]: checked };
                            const required = checked
                              ? current.required
                              : { ...current.required, [name]: false };
                            return { enabled, required };
                          })
                        }
                      />
                      <FormHelperText>
                        <Text component={TextVariants.small}>
                          {t(`edcMfaChannel_${name}_hint`)}
                        </Text>
                      </FormHelperText>
                      <Switch
                        id={`edc-mfa-required-${name}`}
                        name={`edc-mfa-required-${name}`}
                        className="pf-v5-u-ml-md"
                        label={t("edcMfaRequired")}
                        isDisabled={!draft.enabled[name]}
                        isChecked={draft.required[name]}
                        onChange={(_event, checked) =>
                          setDraft((current) => ({
                            ...current,
                            required: { ...current.required, [name]: checked },
                          }))
                        }
                      />
                      <FormHelperText>
                        <Text component={TextVariants.small}>
                          {t(`edcMfaRequired_${name}_hint`)}
                        </Text>
                      </FormHelperText>
                    </div>
                  ))}

                  {requiredCount > 0 && (
                    <Alert
                      isInline
                      variant={AlertVariant.info}
                      title={t("edcMfaRequiredExplainer")}
                      className="pf-v5-u-mt-sm"
                    />
                  )}

                  {!telegramConfigured && (
                    <Alert
                      isInline
                      variant={AlertVariant.warning}
                      title={t("edcMfaTelegramNotConfigured")}
                      className="pf-v5-u-mt-sm"
                    />
                  )}

                  {noneEnabled && (
                    <Alert
                      isInline
                      variant={AlertVariant.warning}
                      title={t("edcMfaNoneEnabled")}
                      className="pf-v5-u-mt-sm"
                    />
                  )}
                </FormGroup>

                <SaveRow
                  saving={saving}
                  disabled={!dirty || noneEnabled}
                  onRevert={() => stored && setDraft(stored)}
                />
              </Form>
            </CardBody>
          </Card>
        )}

        {!loading && !loadError && activeTab === 1 && (
          <Card>
            <CardBody>
              <Toolbar id="apps-toolbar" className="pf-v5-u-mb-md">
                <ToolbarContent>
                  <ToolbarItem>
                    <SearchInput
                      placeholder={t("edcMfaSearchApplications")}
                      value={search}
                      onChange={(_event, val) => setSearch(val)}
                      onClear={() => setSearch("")}
                      style={{ width: "280px" }}
                    />
                  </ToolbarItem>
                  <ToolbarItem align={{ default: "alignRight" }}>
                    <span
                      style={{
                        background: "#f0f4f8",
                        color: "#151515",
                        padding: "6px 14px",
                        borderRadius: "16px",
                        fontSize: "13px",
                      }}
                    >
                      {t("edcMfaWritesApplicationConfig")}
                    </span>
                  </ToolbarItem>
                </ToolbarContent>
              </Toolbar>

              <Table aria-label="Applications MFA Policy Table">
                <Thead>
                  <Tr>
                    <Th>{t("edcMfaColApplication")}</Th>
                    <Th>{t("edcMfaColChannels")}</Th>
                    <Th>{t("edcMfaColLastChanged")}</Th>
                    <Th aria-hidden="true" />
                  </Tr>
                </Thead>
                <Tbody>
                  {filteredApps.map((app) => (
                    <Tr key={app.clientId}>
                        <Td dataLabel={t("edcMfaColApplication")}>
                          <Text component={TextVariants.p}>
                            <strong>{app.name || app.clientId}</strong>
                            {app.inherited && (
                              <Label isCompact color="blue" variant="outline" className="pf-v5-u-ml-sm">
                                {t("edcMfaInherited")}
                              </Label>
                            )}
                          </Text>
                          {app.name && app.name !== app.clientId && (
                            <Text component={TextVariants.small} style={{ color: "#6a6e73" }}>
                              {app.clientId}
                            </Text>
                          )}
                        </Td>
                        <Td dataLabel={t("edcMfaColChannels")}>
                          {/* Two things in one cell, because they are two halves of one decision and
                              a reader needs both at once: colour says whether ICT has left the
                              channel usable for this application, and the marker says whether a user
                              is compelled to set it up. The Second step column used to carry the
                              second half on its own - as one switch for all three channels, which is
                              what made it ambiguous. */}
                          <div style={{ display: "flex", gap: "6px", flexWrap: "wrap" }}>
                            {CHANNEL_NAMES.map((ch) => {
                              const channelState = app.channels.find((c) => c.channel === ch);
                              const isEnabled = channelState?.enabled ?? false;
                              // The server refuses to require a channel that is switched off, so this
                              // cannot arrive - masked anyway so a stored pair that disagrees renders
                              // as inert rather than as a requirement that is not in force.
                              const isRequired = isEnabled && (channelState?.required ?? false);
                              return (
                                <Label
                                  key={ch}
                                  color={isEnabled ? "green" : "grey"}
                                  variant="outline"
                                  style={{
                                    fontWeight: 600,
                                    opacity: isEnabled ? 1 : 0.6,
                                    borderColor: isEnabled ? "#388e3c" : "#d2d2d2",
                                    color: isEnabled ? "#1e4620" : "#6a6e73",
                                    borderRadius: "16px",
                                    padding: "4px 10px",
                                  }}
                                >
                                  {t(`edcMfaChannel_${ch}`)}
                                  {isRequired && (
                                    <span className="pf-v5-u-ml-xs pf-v5-u-font-weight-bold">
                                      · {t("edcMfaChipRequired")}
                                    </span>
                                  )}
                                </Label>
                              );
                            })}
                          </div>
                        </Td>
                        <Td dataLabel={t("edcMfaColLastChanged")}>
                          {app.lastChanged ? formatDate(app.lastChanged) : (app.inherited ? t("edcMfaInherited") : "—")}
                        </Td>
                        <Td isActionCell>
                          <AppActionDropdown
                            app={app}
                            onEdit={() => setEditingApp(app)}
                            onReset={() => handleResetAppToDefault(app.clientId)}
                          />
                        </Td>
                    </Tr>
                  ))}
                </Tbody>
              </Table>

              <div className="pf-v5-u-mt-md" style={{ display: "flex", justifyContent: "flex-end" }}>
                <Text component={TextVariants.small} style={{ color: "#6a6e73" }}>
                  1 - {filteredApps.length} of {applications.length}
                </Text>
              </div>

              <Text component={TextVariants.small} style={{ color: "#6a6e73" }} className="pf-v5-u-mt-sm">
                {t("edcMfaChannelsHint")}
              </Text>

              <div
                style={{
                  borderLeft: "4px solid #0066cc",
                  padding: "12px 16px",
                  background: "#f5f9fc",
                  marginTop: "24px",
                  borderRadius: "0 4px 4px 0",
                }}
              >
                <Text component={TextVariants.small} style={{ color: "#151515", fontSize: "13px" }}>
                  {t("edcMfaBottomCallout")}
                </Text>
              </div>
            </CardBody>
          </Card>
        )}
      </PageSection>

      <AppEditModal
        app={editingApp}
        isOpen={!!editingApp}
        onClose={() => setEditingApp(null)}
        onSave={handleSaveAppModal}
        saving={saving}
      />

    </>
  );
}
