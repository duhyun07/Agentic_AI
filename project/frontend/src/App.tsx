import { BrowserRouter, Routes, Route } from 'react-router-dom';
import Layout from './components/Layout';
import CrashDetail from './pages/CrashDetail';
import Dashboard from './pages/Dashboard';
import Search from './pages/Search';

export default function App() {
  return (
    <BrowserRouter>
      <Layout>
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/crashes/:id" element={<CrashDetail />} />
          <Route path="/search" element={<Search />} />
        </Routes>
      </Layout>
    </BrowserRouter>
  );
}
