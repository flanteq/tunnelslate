import { createApp } from 'vue'
import App from './App.vue'
import ClientPortal from './ClientPortal.vue'
import './style.css'
import './management.css'
import './panels.css'

createApp(location.pathname === new URL('profiles/', document.baseURI).pathname ? ClientPortal : App).mount('#app')
