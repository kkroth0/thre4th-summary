import { createContext, useContext } from 'react';

export const WorkspaceNavigationContext = createContext<{ openMenu: () => void } | null>(null);
export const useWorkspaceNavigation = () => useContext(WorkspaceNavigationContext);
