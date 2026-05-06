import type { ComponentType, LazyExoticComponent } from 'react';
import type { LucideIcon } from 'lucide-react';

export interface PluginRouteConfig {
  path: string;
  component: ComponentType<any> | LazyExoticComponent<ComponentType<any>>;
  pluginId: string;
  pluginName: string;
  label?: string;
  requiresRole?: string[];
}

export interface PluginNavItem {
  id: string;
  path: string;
  label: string;
  icon?: string | LucideIcon;
  priority?: number;
  tourId?: string;
}

export interface PluginPublicPage {
  pluginId: string;
  pluginName: string;
  path: string;
  uiEntry: string;
}
