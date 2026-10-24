import { createContext, useContext } from "react";
import type { Api } from "./api";
import type { Catalog, ServerStatus } from "./types";

export interface AppState {
  api: Api;
  server: ServerStatus | null;
  catalog: Catalog | null;
  /** Call when a request comes back 401, so the interface asks for the API key. */
  requireKey: () => void;
}

export const AppContext = createContext<AppState | null>(null);

export function useApp(): AppState {
  const state = useContext(AppContext);
  if (!state) throw new Error("useApp must be used inside the application.");
  return state;
}
