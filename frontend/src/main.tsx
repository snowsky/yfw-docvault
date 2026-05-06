import React from 'react';
import ReactDOM from 'react-dom/client';
import { Toaster } from 'sonner';

import DocVault from './DocVault';
import './index.css';

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <DocVault />
    <Toaster richColors position="top-right" />
  </React.StrictMode>,
);
