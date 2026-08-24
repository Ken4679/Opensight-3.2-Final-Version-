import React from 'react'
import ReactDOM from 'react-dom/client'
import App from './App' // 去掉 .tsx 后缀
import './index.css'

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
)
