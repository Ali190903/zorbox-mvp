import { render, screen } from '@testing-library/react'
import '@testing-library/jest-dom'
import React from 'react'
import App from './App.jsx'

test('renders ZORBOX UI title', () => {
  render(<App />)
  expect(screen.getByText(/ZORBOX UI/i)).toBeInTheDocument()
})

