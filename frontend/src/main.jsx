import React from 'react'
import ReactDOM from 'react-dom/client'
import App from './App.jsx'
import './index.css'
import { ToastContainer } from 'react-toastify'
import 'react-toastify/dist/ReactToastify.css'

ReactDOM.createRoot(document.getElementById('root')).render(
  <React.StrictMode>
    <App />
    <ToastContainer
      position="bottom-right"
      autoClose={4000}
      hideProgressBar={false}
      newestOnTop
      closeOnClick
      pauseOnHover
      theme="dark"
      toastStyle={{
        background: '#111827',
        border: '1px solid #1f2937',
        color: '#f9fafb',
        fontFamily: 'Inter, sans-serif',
        fontSize: '0.8rem',
      }}
    />
  </React.StrictMode>,
)
