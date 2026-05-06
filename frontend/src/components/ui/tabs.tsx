import React from 'react';
import { cx, type PrimitiveProps } from './primitives';

const TabsContext = React.createContext<{ value: string; onValueChange: (value: string) => void } | null>(null);

export function Tabs({ value, onValueChange, children }: { value: string; onValueChange: (value: string) => void; children: React.ReactNode }) {
  return <TabsContext.Provider value={{ value, onValueChange }}>{children}</TabsContext.Provider>;
}

export function TabsList({ className, ...props }: PrimitiveProps<'div'>) {
  return <div className={cx('dv-tabs-list', className)} {...props} />;
}

export function TabsTrigger({ value, className, ...props }: PrimitiveProps<'button'> & { value: string }) {
  const ctx = React.useContext(TabsContext);
  return (
    <button
      type="button"
      className={cx('dv-tab-trigger', ctx?.value === value && 'dv-tab-active', className)}
      onClick={() => ctx?.onValueChange(value)}
      {...props}
    />
  );
}

export function TabsContent({ value, className, ...props }: PrimitiveProps<'div'> & { value: string }) {
  const ctx = React.useContext(TabsContext);
  if (ctx?.value !== value) return null;
  return <div className={cx('dv-tabs-content', className)} {...props} />;
}
