import { createContext, useContext, useMemo, type ReactNode } from "react";
import { createVaultServiceClient, type VaultServiceClient } from "./client.js";

const VaultServiceContext = createContext<VaultServiceClient | undefined>(undefined);

export interface VaultServiceProviderProps {
  /** Base URL of the API process registering @hakeee/vault-service's routes - e.g. your app's VITE_API_URL. */
  baseUrl: string;
  children: ReactNode;
}

export function VaultServiceProvider({ baseUrl, children }: VaultServiceProviderProps) {
  const client = useMemo(() => createVaultServiceClient(baseUrl), [baseUrl]);
  return <VaultServiceContext.Provider value={client}>{children}</VaultServiceContext.Provider>;
}

export function useVaultServiceClient(): VaultServiceClient {
  const client = useContext(VaultServiceContext);
  if (!client) {
    throw new Error("useVaultServiceClient must be used within a <VaultServiceProvider>");
  }
  return client;
}
