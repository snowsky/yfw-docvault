import React from 'react';
import ReactDOM from 'react-dom/client';
import { Toaster } from 'sonner';

import DocVault from './DocVault';
import SharedDocVaultItemPage from './SharedDocVaultItem';
import './index.css';

const Page = window.location.pathname.startsWith('/shared/') ? SharedDocVaultItemPage : DocVault;

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <Page />
    <Toaster richColors position="top-right" />
  </React.StrictMode>,
);
