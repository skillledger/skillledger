"use client"

import { useRef, useEffect, useState } from "react"
import gsap from "gsap"
import { $api } from "@/lib/api"
import { fetchClient } from "@/lib/api-client"
import { useOrg } from "@/hooks/use-org"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Skeleton } from "@/components/ui/skeleton"
import { useQueryClient } from "@tanstack/react-query"

export default function SsoConfigPage() {
  const containerRef = useRef<HTMLDivElement>(null)
  const queryClient = useQueryClient()
  const { orgSlug, isLoading: orgLoading } = useOrg()

  const [metadataXml, setMetadataXml] = useState("")
  const [entityId, setEntityId] = useState("")
  const [ssoUrl, setSsoUrl] = useState("")
  const [certificate, setCertificate] = useState("")
  const [useManual, setUseManual] = useState(false)
  const [isSaving, setIsSaving] = useState(false)
  const [saveError, setSaveError] = useState("")
  const [saveSuccess, setSaveSuccess] = useState(false)

  useEffect(() => {
    if (containerRef.current) {
      gsap.from(containerRef.current, {
        opacity: 0,
        y: 8,
        duration: 0.3,
        ease: "power2.out",
      })
    }
  }, [])

  const {
    data: samlConfig,
    isLoading: samlLoading,
    error: samlError,
  } = $api.useQuery(
    "get",
    "/ee/v1/orgs/{slug}/saml",
    { params: { path: { slug: orgSlug! } } },
    { enabled: !!orgSlug, retry: false }
  )

  // Pre-fill from existing config
  useEffect(() => {
    if (samlConfig && typeof samlConfig === "object") {
      const config = samlConfig as {
        entity_id?: string
        sso_url?: string
        has_metadata_xml?: boolean
      }
      if (config.entity_id) setEntityId(config.entity_id)
      if (config.sso_url) setSsoUrl(config.sso_url)
      if (config.has_metadata_xml) {
        setUseManual(false)
      } else if (config.entity_id) {
        setUseManual(true)
      }
    }
  }, [samlConfig])

  const isConfigured =
    !samlError && samlConfig && typeof samlConfig === "object"
  const isLoading = orgLoading || samlLoading

  function handleFileChange(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0]
    if (!file) return
    const reader = new FileReader()
    reader.onload = (ev) => {
      const text = ev.target?.result
      if (typeof text === "string") {
        setMetadataXml(text)
      }
    }
    reader.readAsText(file)
  }

  async function handleSave() {
    if (!orgSlug) return
    setIsSaving(true)
    setSaveError("")
    setSaveSuccess(false)

    try {
      const body = useManual
        ? {
            entity_id: entityId,
            sso_url: ssoUrl,
            x509_cert: certificate,
          }
        : {
            metadata_xml: metadataXml,
          }

      await fetchClient.PUT("/ee/v1/orgs/{slug}/saml", {
        params: { path: { slug: orgSlug } },
        body,
      })

      setSaveSuccess(true)
      queryClient.invalidateQueries({
        queryKey: ["get", "/ee/v1/orgs/{slug}/saml"],
      })
      setTimeout(() => setSaveSuccess(false), 5000)
    } catch (err) {
      setSaveError(
        err instanceof Error ? err.message : "Failed to save SSO configuration"
      )
    } finally {
      setIsSaving(false)
    }
  }

  function handleTestConnection() {
    if (!orgSlug) return
    const apiUrl = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000"
    window.open(
      `${apiUrl}/ee/v1/saml/${encodeURIComponent(orgSlug)}/login`,
      "_blank"
    )
  }

  const canSave = useManual
    ? entityId.trim() && ssoUrl.trim() && certificate.trim()
    : metadataXml.trim()

  return (
    <div ref={containerRef} className="space-y-6">
      <div className="flex items-center gap-3">
        <h1 className="text-2xl font-semibold">SSO Configuration</h1>
        {!isLoading && (
          <Badge
            variant="outline"
            className={
              isConfigured
                ? "bg-green-500/10 text-green-500 border-green-500/20"
                : "bg-gray-500/10 text-gray-400 border-gray-400/20"
            }
          >
            {isConfigured ? "Configured" : "Not Configured"}
          </Badge>
        )}
      </div>

      {isLoading ? (
        <div className="space-y-4">
          <Skeleton className="h-12 w-full" />
          <Skeleton className="h-12 w-full" />
          <Skeleton className="h-12 w-full" />
        </div>
      ) : (
        <>
          {saveSuccess && (
            <div
              role="status"
              className="rounded-lg border border-green-500/50 bg-green-500/10 px-3 py-2 text-sm text-green-600"
            >
              SSO configuration saved successfully.
            </div>
          )}

          {saveError && (
            <div
              role="alert"
              className="rounded-lg border border-destructive/50 bg-destructive/10 px-3 py-2 text-sm text-destructive"
            >
              {saveError}
            </div>
          )}

          {/* Section 1: Metadata Upload (default view) */}
          {!useManual && (
            <Card>
              <CardHeader>
                <CardTitle className="text-lg font-semibold">
                  Upload IdP Metadata XML
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div>
                  <Label htmlFor="metadata-upload" className="text-sm">
                    Select an XML metadata file from your Identity Provider
                  </Label>
                  <input
                    id="metadata-upload"
                    type="file"
                    accept=".xml"
                    onChange={handleFileChange}
                    className="mt-2 block w-full text-sm text-muted-foreground file:mr-4 file:rounded-lg file:border-0 file:bg-primary file:px-4 file:py-2 file:text-sm file:font-medium file:text-primary-foreground hover:file:bg-primary/80 file:cursor-pointer"
                  />
                  {metadataXml && (
                    <p className="mt-2 text-xs text-muted-foreground">
                      Metadata loaded ({metadataXml.length} characters)
                    </p>
                  )}
                </div>

                <button
                  type="button"
                  className="text-sm text-primary underline-offset-4 hover:underline"
                  onClick={() => setUseManual(true)}
                >
                  Or configure manually
                </button>
              </CardContent>
            </Card>
          )}

          {/* Section 2: Manual Configuration */}
          {useManual && (
            <Card>
              <CardHeader>
                <CardTitle className="text-lg font-semibold">
                  Manual Configuration
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div>
                  <Label htmlFor="entity-id">Entity ID</Label>
                  <Input
                    id="entity-id"
                    placeholder="https://idp.example.com/entity"
                    value={entityId}
                    onChange={(e) => setEntityId(e.target.value)}
                  />
                </div>

                <div>
                  <Label htmlFor="sso-url">SSO URL</Label>
                  <Input
                    id="sso-url"
                    placeholder="https://idp.example.com/sso"
                    value={ssoUrl}
                    onChange={(e) => setSsoUrl(e.target.value)}
                  />
                </div>

                <div>
                  <Label htmlFor="certificate">X.509 Certificate</Label>
                  <textarea
                    id="certificate"
                    rows={6}
                    placeholder="-----BEGIN CERTIFICATE-----&#10;...&#10;-----END CERTIFICATE-----"
                    value={certificate}
                    onChange={(e) => setCertificate(e.target.value)}
                    className="mt-1 w-full rounded-lg border border-input bg-transparent px-3 py-2 font-mono text-sm text-foreground placeholder:text-muted-foreground focus-visible:border-ring focus-visible:ring-3 focus-visible:ring-ring/50 focus-visible:outline-none"
                  />
                </div>

                <button
                  type="button"
                  className="text-sm text-primary underline-offset-4 hover:underline"
                  onClick={() => setUseManual(false)}
                >
                  Use metadata upload
                </button>
              </CardContent>
            </Card>
          )}

          {/* Action Buttons */}
          <div className="flex items-center gap-3">
            <Button
              variant="default"
              disabled={isSaving || !canSave}
              onClick={handleSave}
            >
              {isSaving ? "Saving..." : "Save SSO Configuration"}
            </Button>

            <Button
              variant="outline"
              onClick={handleTestConnection}
              disabled={!isConfigured}
            >
              Test Connection
            </Button>
          </div>
        </>
      )}
    </div>
  )
}
