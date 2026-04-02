import { BrowserRouter, Routes, Route } from 'react-router-dom';
import Layout from './components/Layout';
import Dashboard from './pages/Dashboard';
import ScanProgress from './pages/ScanProgress';
import ScanDetail from './pages/ScanDetail';
import ScanHistory from './pages/ScanHistory';
import Settings from './pages/Settings';

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route element={<Layout />}>
          <Route path="/" element={<Dashboard />} />
          <Route path="/scans" element={<ScanHistory />} />
          <Route path="/scans/:id" element={<ScanDetail />} />
          <Route path="/scans/:id/progress" element={<ScanProgress />} />
          <Route path="/settings" element={<Settings />} />
        </Route>
      </Routes>
    </BrowserRouter>
  );
}
